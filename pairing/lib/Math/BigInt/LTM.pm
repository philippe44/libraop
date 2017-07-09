package Math::BigInt::LTM;

use strict;
use warnings;
our $VERSION = '0.048';

use CryptX;

sub api_version() { 2 }

sub CLONE_SKIP { 1 } # prevent cloning

### same as overloading in Math::BigInt::Lib
use overload
  # overload key: with_assign

  '+'    => sub {
                my $class = ref $_[0];
                my $x = $class -> _copy($_[0]);
                my $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                return $class -> _add($x, $y);
            },

  '-'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _sub($x, $y);
            },

  '*'    => sub {
                my $class = ref $_[0];
                my $x = $class -> _copy($_[0]);
                my $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                return $class -> _mul($x, $y);
            },

  '/'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _div($x, $y);
            },

  '%'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _mod($x, $y);
            },

  '**'   => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _pow($x, $y);
            },

  '<<'   => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $class -> _num($_[0]);
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $_[0];
                    $y = ref($_[1]) ? $class -> _num($_[1]) : $_[1];
                }
                return $class -> _blsft($x, $y);
            },

  '>>'   => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _brsft($x, $y);
            },

  # overload key: num_comparison

  '<'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _acmp($x, $y) < 0;
            },

  '<='   => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _acmp($x, $y) <= 0;
            },

  '>'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _acmp($x, $y) > 0;
            },

  '>='   => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _acmp($x, $y) >= 0;
          },

  '=='   => sub {
                my $class = ref $_[0];
                my $x = $class -> _copy($_[0]);
                my $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                return $class -> _acmp($x, $y) == 0;
            },

  '!='   => sub {
                my $class = ref $_[0];
                my $x = $class -> _copy($_[0]);
                my $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                return $class -> _acmp($x, $y) != 0;
            },

  # overload key: 3way_comparison

  '<=>'  => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _acmp($x, $y);
            },

  # overload key: binary

  '&'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _and($x, $y);
            },

  '|'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _or($x, $y);
            },

  '^'    => sub {
                my $class = ref $_[0];
                my ($x, $y);
                if ($_[2]) {            # if swapped
                    $y = $_[0];
                    $x = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                } else {
                    $x = $class -> _copy($_[0]);
                    $y = ref($_[1]) ? $_[1] : $class -> _new($_[1]);
                }
                return $class -> _xor($x, $y);
            },

  # overload key: func

  'abs'  => sub { $_[0] },

  'sqrt' => sub {
                my $class = ref $_[0];
                return $class -> _sqrt($class -> _copy($_[0]));
            },

  'int'  => sub { $_[0] -> copy() -> bint(); },

  # overload key: conversion

  'bool' => sub { ref($_[0]) -> _is_zero($_[0]) ? '' : 1; },

  '""'   => sub { ref($_[0]) -> _str($_[0]); },

  '0+'   => sub { ref($_[0]) -> _num($_[0]); },

  '='    => sub { ref($_[0]) -> _copy($_[0]); },

  ;

### same as import() in Math::BigInt::Lib
sub import { }

### same as _check() in Math::BigInt::Lib
sub _check {
  # used by the test suite
  my ($class, $x) = @_;
  return "Input is undefined" unless defined $x;
  return "$x is not a reference" unless ref($x);
  return 0;
}

### same as _digit() in Math::BigInt::Lib
sub _digit {
  my ($class, $x, $n) = @_;
  substr($class ->_str($x), -($n+1), 1);
}

### same as _num() in Math::BigInt::Lib
sub _num {
  my ($class, $x) = @_;
  0 + $class -> _str($x);
}

### BEWARE!!! NOT THE SAME as _fac() in Math::BigInt::Lib
sub _fac {
  # factorial
  my ($class, $x) = @_;

  my $two = $class -> _two();

  if ($class -> _acmp($x, $two) < 0) {
      $class->_set($x, 1);
      return $x;
  }

  my $i = $class -> _copy($x);
  while ($class -> _acmp($i, $two) > 0) {
      $i = $class -> _dec($i);
      $x = $class -> _mul($x, $i);
  }

  return $x;
}

### same as _nok() in Math::BigInt::Lib
sub _nok {
  # Return binomial coefficient (n over k).
  # Given refs to arrays, return ref to array.
  # First input argument is modified.

  my ($class, $n, $k) = @_;

  # If k > n/2, or, equivalently, 2*k > n, compute nok(n, k) as
  # nok(n, n-k), to minimize the number if iterations in the loop.

  {
      my $twok = $class -> _mul($class -> _two(), $class -> _copy($k));
      if ($class -> _acmp($twok, $n) > 0) {
          $k = $class -> _sub($class -> _copy($n), $k);
      }
  }

  # Example:
  #
  # / 7 \       7!       1*2*3*4 * 5*6*7   5 * 6 * 7       6   7
  # |   | = --------- =  --------------- = --------- = 5 * - * -
  # \ 3 /   (7-3)! 3!    1*2*3*4 * 1*2*3   1 * 2 * 3       2   3

  if ($class -> _is_zero($k)) {
      return $class -> _one();
  }

  # Make a copy of the original n, since we'll be modifying n in-place.

  my $n_orig = $class -> _copy($n);

  # n = 5, f = 6, d = 2 (cf. example above)

  $n = $class -> _sub($n, $k);
  $n = $class -> _inc($n);

  my $f = $class -> _copy($n);
  $class -> _inc($f);

  my $d = $class -> _two();

  # while f <= n (the original n, that is) ...

  while ($class -> _acmp($f, $n_orig) <= 0) {

      # n = (n * f / d) == 5 * 6 / 2 (cf. example above)

      $n = $class -> _mul($n, $f);
      $n = $class -> _div($n, $d);

      # f = 7, d = 3 (cf. example above)

      $f = $class -> _inc($f);
      $d = $class -> _inc($d);
  }

  return $n;
}

### same as _log_int() in Math::BigInt::Lib
sub _log_int {
  # calculate integer log of $x to base $base
  # ref to array, ref to array - return ref to array
  my ($class, $x, $base) = @_;

  # X == 0 => NaN
  return if $class -> _is_zero($x);

  $base = $class -> _new(2)     unless defined($base);
  $base = $class -> _new($base) unless ref($base);

  # BASE 0 or 1 => NaN
  return if $class -> _is_zero($base) || $class -> _is_one($base);

  # X == 1 => 0 (is exact)
  if ($class -> _is_one($x)) {
      return $class -> _zero(), 1;
  }

  my $cmp = $class -> _acmp($x, $base);

  # X == BASE => 1 (is exact)
  if ($cmp == 0) {
      return $class -> _one(), 1;
  }

  # 1 < X < BASE => 0 (is truncated)
  if ($cmp < 0) {
      return $class -> _zero(), 0;
  }

  my $y;

  # log(x) / log(b) = log(xm * 10^xe) / log(bm * 10^be)
  #                 = (log(xm) + xe*(log(10))) / (log(bm) + be*log(10))

  {
      my $x_str = $class -> _str($x);
      my $b_str = $class -> _str($base);
      my $xm    = "." . $x_str;
      my $bm    = "." . $b_str;
      my $xe    = length($x_str);
      my $be    = length($b_str);
      my $log10 = log(10);
      my $guess = int((log($xm) + $xe * $log10) / (log($bm) + $be * $log10));
      $y = $class -> _new($guess);
  }

  my $trial = $class -> _pow($class -> _copy($base), $y);
  my $acmp  = $class -> _acmp($trial, $x);

  # Did we get the exact result?

  return $y, 1 if $acmp == 0;

  # Too small?

  while ($acmp < 0) {
      $trial = $class -> _mul($trial, $base);
      $y     = $class -> _inc($y);
      $acmp  = $class -> _acmp($trial, $x);
  }

  # Too big?

  while ($acmp > 0) {
      $trial = $class -> _div($trial, $base);
      $y     = $class -> _dec($y);
      $acmp  = $class -> _acmp($trial, $x);
  }

  return $y, 1 if $acmp == 0;         # result is exact
  return $y, 0;                       # result is too small
}

1;

__END__

=pod

=head1 NAME

Math::BigInt::LTM - Use the libtommath library for Math::BigInt routines

=head1 SYNOPSIS

 use Math::BigInt lib => 'LTM';

 ## See Math::BigInt docs for usage.

=head1 DESCRIPTION

Provides support for big integer calculations by means of the libtommath c-library.

I<Since: CryptX-0.029>

=head1 SEE ALSO

L<Math::BigInt>, L<https://github.com/libtom/libtommath>

=cut
