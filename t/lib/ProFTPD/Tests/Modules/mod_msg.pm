package ProFTPD::Tests::Modules::mod_msg;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  msg_msgctrl_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

# Support functions

sub ftpdctl {
  my $sock_file = shift;
  my $ctrl_cmd = shift;

  my $ftpdctl_bin;
  if ($ENV{PROFTPD_TEST_DIR}) {
    $ftpdctl_bin = "$ENV{PROFTPD_TEST_DIR}/../ftpdctl";
  
  } else {
    $ftpdctl_bin = '../ftpdctl'; 
  }

  my $verbosity = '';
  if ($ENV{TEST_VERBOSE}) {
    $verbosity = '-v';
  }

  my $cmd = "$ftpdctl_bin -s $sock_file $verbosity $ctrl_cmd";

  if ($ENV{TEST_VERBOSE}) {
    print STDERR "Executing ftpdctl: $cmd\n";
  }

  my @lines = `$cmd`;
  my $exit_status = $? >> 8;

  return ($exit_status, \@lines);
}

my $msg_server_wait_timeout = 0;
sub msg_server_wait_alarm {
  croak("Test timed out after $msg_server_wait_timeout secs");
}

sub msg_server_wait {
  my $config_file = shift;
  my $rfh = shift;
  my $server_wait_timeout = shift;
  $server_wait_timeout = 10 unless defined($server_wait_timeout);
  my $ctrls_sock = shift;
  my $ctrls_cmd = shift;

  # Start server
  server_start($config_file, undef, undef);

  $msg_server_wait_timeout = $server_wait_timeout;
  $SIG{ALRM} = \&msg_server_wait_alarm;
  alarm($server_wait_timeout);

  # Allow for server startup
  sleep(1);

  my ($exit_status, $lines) = ftpdctl($ctrls_sock, $ctrls_cmd);
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# ftpdctl: (exit status $exit_status)\n";
    foreach my $line (@$lines) {
      chomp($line);
      print STDERR "#  $line\n";
    }
  }

  # Wait until we receive word from the child that it has finished its test.
  while (my $msg = <$rfh>) {
    chomp($msg);

    if ($msg eq 'done') {
      last;
    }
  }

  alarm(0);
  $SIG{ALRM} = 'DEFAULT';
  return 1;
}

# Test cases

sub msg_msgctrl_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'msg');

  my $ctrls_sock = File::Spec->rel2abs("$tmpdir/ctrls.sock");
  my $msg_queue = File::Spec->rel2abs("$tmpdir/msg.queue");

  my $phrase = 'I see you, watching your every move';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'ctrls:20 msg:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_ctrls.c' => {
        ControlsEngine => 'on',
        ControlsLog => $setup->{log_file},
        ControlsSocket => $ctrls_sock,
        ControlsSocketACL => 'allow user *',
        ControlsInterval => 2,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_msg.c' => {
        MessageEngine => 'on',
        MessageLog => $setup->{log_file},
        MessageQueue => $msg_queue,
        MessageControlsACLs => 'msg allow user *',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow the server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});

      # Wait for the message to be posted to us
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Pausing for message to be posted\n";
      }
      sleep(5);

      $client->list();
      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      my $resp_msg = $resp_msgs->[0];
      $self->assert_transfer_ok($resp_code, $resp_msg);

      my $resp_phrase = $resp_msgs->[1];
      $self->assert($resp_phrase eq $phrase,
        test_msg("Expected phrase '$phrase', got '$resp_phrase'"));

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { msg_server_wait($setup->{config_file}, $rfh, 15, $ctrls_sock,
      "msg user $setup->{user} $phrase") };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
