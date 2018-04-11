/*
 * ProFTPD: mod_msg -- a module for sending messages to connected clients
 *
 * Copyright (c) 2004 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_msg, contrib software for proftpd 1.2 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * $Id: mod_msg.c,v 1.5 2004/05/26 19:43:18 tj Exp tj $
 */

#include "conf.h"
#include "mod_ctrls.h"
#include "privs.h"

#include <sys/ipc.h>
#include <sys/msg.h>

#ifndef MSGMAX
# define MSGMAX 8192
#endif /* MSGMAX */

#define MOD_MSG_VERSION		"mod_msg/0.4.1"

#if PROFTPD_VERSION_NUMBER < 0x0001021001
# error "ProFTPD 1.2.10rc1 or later required"
#endif

#define MSG_PROJ_ID		246

/* From src/main.c */
extern pid_t mpid;

module msg_module;

#ifndef USE_CTRLS
# error "mod_msg requires Controls support (--enable-ctrls)"
#endif /* USE_CTRLS */

static ctrls_acttab_t msg_acttab[];

static int msg_engine = FALSE;
static int msg_logfd = -1;
static array_header *msg_pending_list = NULL;
static pool *msg_pool = NULL;
static pool *msg_pending_pool = NULL;
static pr_fh_t *msg_queue_fh = NULL;
static char *msg_queue_path = NULL;
static int msg_qid = -1;

/* Define our own structure for messages, since one is not portably defined.
 */
struct mq_msg {
  /* Message type */
  long mtype;

  /* Message data */
  char mtext[1];
};

static key_t msg_get_key(const char *path) {
  pr_fh_t *fh;

  /* ftok() uses stat(2) on the given path, which means that it needs to exist.
   * So stat() the file ourselves first, and create it if necessary.  We need
   * make sure that permissions on the file we create match the ones that
   * mod_xfer would create.
   */
  fh = pr_fsio_open(path, O_WRONLY|O_CREAT);
  if (!fh) {
    (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
      "error opening '%s': %s", path, strerror(errno));
    return -1;
  }
  pr_fsio_close(fh);

  return ftok(path, MSG_PROJ_ID);
}

static int msg_get_queue(const char *path) {
  int qid;

  /* Obtain a key for this path. */
  key_t key = msg_get_key(path);
  if (key == (key_t) -1) {
    (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
      "unable to get key for '%s': %s", path, strerror(errno));
    return -1;
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * queue for this key.  If there is, try again, using a flag of zero.
   */
  qid = msgget(key, IPC_CREAT|IPC_EXCL|0666);
  if (qid < 0) {
    if (errno == EEXIST)
      qid = msgget(key, 0);

    else
      return -1;
  }

  return qid;  
}

static int msg_recv_msg(void) {
  int nmsgs = 0;
  ssize_t msglen = 0;
  char buf[MSGMAX] = {'\0'};
  struct mq_msg *msg;

  if (!msg_pending_list) {
    if (!msg_pending_pool) {
      msg_pending_pool = make_sub_pool(msg_pool);
      pr_pool_tag(msg_pending_pool, MOD_MSG_VERSION ": pending pool");
    }

    msg_pending_list = make_array(msg_pending_pool, 0, sizeof(char *));
  }

  msg = malloc(sizeof(struct mq_msg) + MSGMAX - sizeof(msg->mtext));
  if (!msg)
    end_login(1);

  msglen = msgrcv(msg_qid, msg, sizeof(buf), getpid(),
    IPC_NOWAIT|MSG_NOERROR);

  while (msglen > 0) {
    pr_signals_handle();

    /* msglen is the number of bytes in the message.  This means it does
     * not know of string semantics, hence we need to add one byte for the
     * terminating NUL character.
     */

    *((char **) push_array(msg_pending_list)) = pstrndup(msg_pending_pool,
      msg->mtext, msglen + 1);
    nmsgs++;

    msglen = msgrcv(msg_qid, msg, sizeof(buf), getpid(),
      IPC_NOWAIT|MSG_NOERROR);
  }

  free(msg);

  if (msglen < 0 &&
#ifdef ENOMSG
      errno != ENOMSG &&
#endif /* ENOMSG */
      errno != EAGAIN)
    return -1;

  return nmsgs;
}

static int msg_send_msg(pid_t dst_pid, const char *msgstr) {
  int res;
  struct mq_msg *msg;

  /* Take the terminating NUL into account. */
  size_t msglen = strlen(msgstr) + 1;

  msg = malloc(sizeof(struct mq_msg) + MSGMAX - sizeof(msg->mtext));
  if (!msg)
    end_login(1);

  msg->mtype = dst_pid;
  sstrncpy(msg->mtext, msgstr, msglen);

  while (msgsnd(msg_qid, msg, msglen, IPC_NOWAIT) < 0) {
    pr_signals_handle();

    if (errno != EAGAIN) {
      free(msg);
      return -1;
    }
  }
  free(msg);

  /* Send SIGUSR2 to the destination process, to let it know that it should
   * check the queue for messages.
   */
  PRIVS_ROOT
  res = kill(dst_pid, SIGUSR2);
  PRIVS_RELINQUISH

  if (res < 0)
    (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
      "error sending notice: %s", strerror(errno));

  return 0;
}

/* Configuration handlers
 */

/* usage: MessageControlsACLs actions|all allow|deny user|group list */
MODRET set_msgctrlsacls(cmd_rec *cmd) {
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0)
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0)
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");

  if ((bad_action = ctrls_set_module_acls(msg_acttab, msg_pool,
      actions, cmd->argv[2], cmd->argv[3], cmd->argv[4])) != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));

  return HANDLED(cmd);
}

/* usage: MessageEngine on|off */
MODRET set_msgengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return HANDLED(cmd);
}

/* usage: MessageLog path */
MODRET set_msglog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0)
    CONF_ERROR(cmd, "must be an absolute path");

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return HANDLED(cmd);
}

/* usage: MessageQueue path */
MODRET set_msgqueue(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0)
    CONF_ERROR(cmd, "must be an absolute path");

  msg_queue_path = pstrdup(msg_pool, cmd->argv[1]);
  return HANDLED(cmd);
}

/* Command handlers
 */

MODRET msg_post_any(cmd_rec *cmd) {
  register unsigned int i = 0;
  char **msgs;

  if (!msg_engine)
    return DECLINED(cmd);

  /* If there are no messages pending for this process, be done now. */
  if (!msg_pending_list || msg_pending_list->nelts == 0)
    return DECLINED(cmd);

  /* Skip commands whose reply format is strictly proscribed. */

  /* XXX there are probably more commands to be skipped here */
  if (strcmp(cmd->argv[0], C_EPSV) == 0 ||
      strcmp(cmd->argv[0], C_PASV) == 0 ||
      strcmp(cmd->argv[0], C_STOU) == 0)
    return DECLINED(cmd);

  /* Tack on any messages to this command. */
  msgs = (char **) msg_pending_list->elts;
  for (i = 0; i < msg_pending_list->nelts; i++)
    pr_response_add(R_DUP, msgs[i]);

  /* Clear the pending pool. */
  destroy_pool(msg_pending_pool);
  msg_pending_pool = NULL;
  msg_pending_list = NULL;

  return DECLINED(cmd);
}

MODRET msg_post_err_any(cmd_rec *cmd) {
  register unsigned int i = 0;
  char **msgs;

  if (!msg_engine)
    return DECLINED(cmd);

  /* If there are no messages pending for this process, be done now. */
  if (!msg_pending_list || msg_pending_list->nelts == 0)
    return DECLINED(cmd);

  /* Skip commands whose reply format is strictly proscribed. */

  /* XXX there are probably more commands to be skipped here */
  if (strcmp(cmd->argv[0], C_EPSV) == 0 ||
      strcmp(cmd->argv[0], C_PASV) == 0 ||
      strcmp(cmd->argv[0], C_STOU) == 0)
    return DECLINED(cmd);

  /* Tack on any messages to this command. */
  msgs = (char **) msg_pending_list->elts;
  for (i = 0; i < msg_pending_list->nelts; i++)
    pr_response_add_err(R_DUP, msgs[i]);

  /* Clear the pending pool. */
  destroy_pool(msg_pending_pool);
  msg_pending_pool = NULL;
  msg_pending_list = NULL;

  return DECLINED(cmd);
}

/* Event handlers
 */

static void msg_exit_ev(const void *event_data, void *user_data) {

  /* Remove the queue from the system.  We can only do this reliably
   * when the standalone daemon process exits; if it's an inetd process,
   * there may be other proftpd processes still running.
   */
  if (getpid() == mpid &&
      ServerType == SERVER_STANDALONE) {
    struct msqid_ds ds;

    if (msgctl(msg_qid, IPC_RMID, &ds) < 0 && errno != EINVAL)
      pr_log_debug(DEBUG1, MOD_MSG_VERSION ": error removing queue %d: %s",
        msg_qid, strerror(errno));
  }
}

static void msg_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;

  /* Open the MessageLog for the "server config" server here, if any, for
   * use for logging by the daemon process.
   */

  c = find_config(main_server->conf, CONF_PARAM, "MessageLog", FALSE);
  if (c) {
    const char *path = c->argv[0];

    if (strcasecmp(path, "none") != 0 &&
        pr_log_openfile(path, &msg_logfd, 0660) < 0) {
      pr_log_debug(DEBUG2, MOD_MSG_VERSION
        ": error opening MessageLog '%s': %s", path, strerror(errno));
      msg_logfd = -1;
    }
  }

  if (msg_queue_path)
    msg_queue_fh = pr_fsio_open(msg_queue_path, O_RDWR|O_CREAT);

  else
    errno = EINVAL;

  if (!msg_queue_fh) {
    (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
      "error opening MessageQueue: %s", strerror(errno));

  } else {
    msg_qid = msg_get_queue(msg_queue_path);
    if (msg_qid < 0)
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "error obtaining queue ID: %s", strerror(errno));
else
pr_log_debug(DEBUG0, MOD_MSG_VERSION ": obtained queue ID %d", msg_qid);
  }
}

static void msg_restart_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  if (msg_pool)
    destroy_pool(msg_pool);

  msg_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(msg_pool, MOD_MSG_VERSION);

  for (i = 0; msg_acttab[i].act_action; i++) {
    msg_acttab[i].act_acl = pcalloc(msg_pool, sizeof(ctrls_acl_t));
    ctrls_init_acl(msg_acttab[i].act_acl);
  }
}

static void msg_sigusr2_ev(const void *event_data, void *user_data) {

  /* Check the queue for any messages for us. */
  int res = msg_recv_msg();

  switch (res) {
    case -1:
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "error receiving messages for pid %u: %s", getpid(), strerror(errno));
      break;

    case 0:
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "received notice, no messages for pid %u", getpid());
      break;

    default:
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "received notice, read in %d %s for pid %u", res,
        res == 1 ? "message" : "messages", getpid());
  }
}

static void msg_startup_ev(const void *event_data, void *user_data) {
  int res;

  /* Make sure the process has an fd to the scoreboard. */
  PRIVS_ROOT
  res = pr_open_scoreboard(O_RDWR);
  PRIVS_RELINQUISH

  if (res < 0) {
    switch (res) {
      case PR_SCORE_ERR_BAD_MAGIC:
        pr_log_debug(DEBUG0, "error opening scoreboard: bad/corrupted file");
        break;

      case PR_SCORE_ERR_OLDER_VERSION:
        pr_log_debug(DEBUG0, "error opening scoreboard: bad version (too old)");
        break;

      case PR_SCORE_ERR_NEWER_VERSION:
        pr_log_debug(DEBUG0, "error opening scoreboard: bad version (too new)");
        break;

      default:
        pr_log_debug(DEBUG0, "error opening scoreboard: %s", strerror(errno));
        break;
    }
  }
}

/* Control handlers
 */

/* Handle the 'msg' action */
static int msg_handle_msg(pr_ctrls_t *ctrl, int reqargc, char **reqargv) {
  int res = 0, msg_errno = 0, msg_know_dst = FALSE, msg_sent = FALSE;

  if (!ctrls_check_acl(ctrl, msg_acttab, "msg")) {
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "missing required parameters");
    return -1;
  }

  /* Handle 'msg user' requests. */
  if (strcmp(reqargv[0], "user") == 0) {
    register unsigned int i = 0;
    pr_scoreboard_entry_t *score = NULL;
    const char *user, *msgstr = "";
    size_t msglen;

    if (reqargc == 1) {
      pr_ctrls_add_response(ctrl, "msg user: missing required user name");
      return -1;
    }

    if (reqargc == 2) {
      pr_ctrls_add_response(ctrl, "msg user: missing required message");
      return -1;
    }

    user = reqargv[1];

    /* Concatenate the given message into a single string.  There may need to
     * be a maximum length on this strength, depending on the maximum msg
     * size allowed for SysV message queues.
     */
    for (i = 2; i < reqargc; i++)
      msgstr = pstrcat(ctrl->ctrls_tmp_pool, msgstr, *msgstr ? " " : "",
        reqargv[i], NULL);

    msglen = strlen(msgstr) + 1;

    if (msglen == 0) {
      pr_ctrls_add_response(ctrl, "zero length message not allowed");
      return -1;
    }

    if (msglen >= MSGMAX) {
      pr_ctrls_add_response(ctrl, "message exceeds maximum length (%u). "
        "Try sending smaller messages", MSGMAX);
      return -1;
    }

    /* Iterate through the scoreboard, looking for any sessions for the
     * given user.
     */
    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    while ((score = pr_scoreboard_read_entry()) != NULL) {
      if (strcmp(user, score->sce_user) == 0) {
        msg_know_dst = TRUE;

        if (msg_send_msg(score->sce_pid, msgstr) < 0) {
          msg_errno = errno;
          (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
            "error sending message to user '%s' (pid %u): %s", user,
            score->sce_pid, strerror(errno));

        } else
          msg_sent = TRUE;
      }
    }

    pr_restore_scoreboard();

  /* Handle 'msg host' requests. */
  } else if (strcmp(reqargv[0], "host") == 0) {
    register unsigned int i = 0;
    pr_scoreboard_entry_t *score = NULL;
    const char *addr, *msgstr = "";
    pr_netaddr_t *na;

    if (reqargc == 1) {
      pr_ctrls_add_response(ctrl, "msg host: missing required host name");
      return -1;
    }

    if (reqargc == 2) {
      pr_ctrls_add_response(ctrl, "msg host: missing required message");
      return -1;
    }

    /* Concatenate the given message into a single string.  There may need to
     * be a maximum length on this strength, depending on the maximum msg
     * size allowed for SysV message queues.
     */
    for (i = 2; i < reqargc; i++)
      msgstr = pstrcat(ctrl->ctrls_tmp_pool, msgstr, *msgstr ? " " : "",
        reqargv[i], NULL);

    if (strlen(msgstr) >= MSGMAX) {
      pr_ctrls_add_response(ctrl, "message exceeds maximum length (%u). "
        "Try sending smaller messages", MSGMAX);
      return -1;
    }

    na = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, reqargv[1], NULL);
    if (!na) {
      pr_ctrls_add_response(ctrl, "msg host: error resolving '%s': %s",
        reqargv[1], strerror(errno));
      return -1;
    }

    addr = pr_netaddr_get_ipstr(na);

    /* Iterate through the scoreboard, looking for any sessions for the
     * given address.
     */
    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    while ((score = pr_scoreboard_read_entry()) != NULL) {
      if (strcmp(addr, score->sce_client_addr) == 0) {
        msg_know_dst = TRUE;

        if (msg_send_msg(score->sce_pid, msgstr) < 0) {
          msg_errno = errno;
          (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
            "error sending message to host '%s' (pid %u): %s", reqargv[1],
            score->sce_pid, strerror(errno));

        } else
          msg_sent = TRUE;
      }
    }

    pr_restore_scoreboard();

  /* Handle 'msg class' requests. */
  } else if (strcmp(reqargv[0], "class") == 0) {
    register unsigned int i = 0;
    pr_scoreboard_entry_t *score;
    const char *class = reqargv[1], *msgstr = "";

    if (reqargc == 1) {
      pr_ctrls_add_response(ctrl, "msg class: missing required class name");
      return -1;
    }

    if (reqargc == 2) {
      pr_ctrls_add_response(ctrl, "msg class: missing required message");
      return -1;
    }

    /* Concatenate the given message into a single string.  There may need to
     * be a maximum length on this strength, depending on the maximum msg
     * size allowed for SysV message queues.
     */
    for (i = 2; i < reqargc; i++)
      msgstr = pstrcat(ctrl->ctrls_tmp_pool, msgstr, *msgstr ? " " : "",
        reqargv[i], NULL);

    if (strlen(msgstr) >= MSGMAX) {
      pr_ctrls_add_response(ctrl, "message exceeds maximum length (%u). "
        "Try sending smaller messages", MSGMAX);
      return -1;
    }

    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    while ((score = pr_scoreboard_read_entry()) != NULL) {
      if (strcmp(score->sce_class, class) == 0) {
        msg_know_dst = TRUE;

        if (msg_send_msg(score->sce_pid, msgstr) < 0) {
          msg_errno = errno;
          (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
            "error sending message to class '%s' (pid %u): %s", reqargv[1],
            score->sce_pid, strerror(errno));

        } else
          msg_sent = TRUE;
      }
    }

    pr_restore_scoreboard();

  /* Handle 'msg all' requests. */
  } else if (strcmp(reqargv[0], "all") == 0) {
    register unsigned int i = 0;
    pr_scoreboard_entry_t *score;
    const char *msgstr = "";

    if (reqargc == 1) {
      pr_ctrls_add_response(ctrl, "msg all: missing required message");
      return -1;
    }

    /* Concatenate the given message into a single string.  There may need to
     * be a maximum length on this strength, depending on the maximum msg
     * size allowed for SysV message queues.
     */
    for (i = 1; i < reqargc; i++)
      msgstr = pstrcat(ctrl->ctrls_tmp_pool, msgstr, *msgstr ? " " : "",
        reqargv[i], NULL);

    if (strlen(msgstr) >= MSGMAX) {
      pr_ctrls_add_response(ctrl, "message exceeds maximum length (%u). "
        "Try sending smaller messages", MSGMAX);
      return -1;
    }

    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    msg_know_dst = TRUE;
    while ((score = pr_scoreboard_read_entry()) != NULL) {
      if (msg_send_msg(score->sce_pid, msgstr) < 0) {
        msg_errno = errno;
        (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
          "error sending message to all (pid %u): %s", reqargv[1],
          score->sce_pid, strerror(errno));

      } else
        msg_sent = TRUE;
    }

    pr_restore_scoreboard();

  } else {
    pr_ctrls_add_response(ctrl, "unknown msg type requested: '%s'",
      reqargv[0]);
    return -1;
  }

  if (msg_sent)
    pr_ctrls_add_response(ctrl, "message sent");

  else if (!msg_know_dst)
    pr_ctrls_add_response(ctrl, "unable to send message: "
      "no such client connected");

  else
    pr_ctrls_add_response(ctrl, "error sending message: %s",
      strerror(msg_errno));

  return res;
}

/* Initialization functions
 */

static int msg_init(void) {
  register unsigned int i;

  msg_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(msg_pool, MOD_MSG_VERSION);

  for (i = 0; msg_acttab[i].act_action; i++) {
    msg_acttab[i].act_acl = pcalloc(msg_pool, sizeof(ctrls_acl_t));
    ctrls_init_acl(msg_acttab[i].act_acl);

    if (pr_ctrls_register(&msg_module, msg_acttab[i].act_action,
        msg_acttab[i].act_desc, msg_acttab[i].act_cb) < 0)
      pr_log_pri(PR_LOG_INFO, MOD_MSG_VERSION
        ": error registering '%s' control: %s",
        msg_acttab[i].act_action, strerror(errno));
  }

  pr_event_register(&msg_module, "core.exit", msg_exit_ev, NULL);
  pr_event_register(&msg_module, "core.postparse", msg_postparse_ev, NULL);
  pr_event_register(&msg_module, "core.restart", msg_restart_ev, NULL);
  pr_event_register(&msg_module, "core.startup", msg_startup_ev, NULL);

  return 0;
}

static int msg_sess_init(void) {
  config_rec *c;

  /* If there was an error opening the MessageQueue, force the module to
   * be inoperative.  We'd much rather not operate without the MessageQueue.
   */
  if (!msg_queue_fh) {
    msg_engine = FALSE;
    (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
      "missing required MessageQueue, disabling module");
    return 0;
  }

  /* If we don't have the qid, it's pointless to continue further. */
  if (msg_qid < 0) {
    (void) pr_log_writefile(msg_logfd, MOD_MSG_VERSION,
      "missing required queue ID, disabling module");
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "MessageEngine", FALSE);
  if (c &&
      *((unsigned char *) c->argv[0]) == TRUE)
    msg_engine = TRUE;

  if (!msg_engine)
    return 0;

  pr_event_register(&msg_module, "core.signal.USR2", msg_sigusr2_ev, NULL);
  pr_event_unregister(&msg_module, "core.exit", msg_exit_ev);

  return 0;
}

static ctrls_acttab_t msg_acttab[] = {
  { "msg",	"send messages to connected clients",	NULL,	msg_handle_msg},
  { NULL, NULL, NULL, NULL }
};

/* Module API tables
 */

static conftable msg_conftab[] = {
  { "MessageControlsACLs",	set_msgctrlsacls,	NULL },
  { "MessageEngine",		set_msgengine,		NULL },
  { "MessageLog",		set_msglog,		NULL },
  { "MessageQueue",		set_msgqueue,		NULL },
  { NULL }
};

static cmdtable msg_cmdtab[] = {
  { POST_CMD,		C_ANY,	G_NONE,	msg_post_any,		FALSE,	FALSE },
  { POST_CMD_ERR,	C_ANY,	G_NONE,	msg_post_err_any,	FALSE,	FALSE },
  { 0, NULL }
};

module msg_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "msg",

  /* Module configuration handler table */
  msg_conftab,

  /* Module command handler table */
  msg_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  msg_init,

  /* Session initialization function */
  msg_sess_init
};
