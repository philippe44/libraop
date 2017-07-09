package Crypt::PK::DH;

use strict;
use warnings;
our $VERSION = '0.048';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( dh_encrypt dh_decrypt dh_sign_message dh_verify_message dh_sign_hash dh_verify_hash dh_shared_secret )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
use CryptX;
use Crypt::Digest 'digest_data';
use Crypt::Misc qw(read_rawfile);

my %DH_PARAMS = (
  ike768  => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF'
  },
  ike1024 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381'.
                            'FFFFFFFFFFFFFFFF'
  },
  ike1536 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
                            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
                            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
                            '670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF'
  },
  ike2048 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
                            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
                            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
                            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
                            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'.
                            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
                            '15728E5A8AACAA68FFFFFFFFFFFFFFFF'
  },
  ike3072 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
                            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
                            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
                            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
                            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'.
                            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
                            '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64'.
                            'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'.
                            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B'.
                            'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'.
                            'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31'.
                            '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
  },
  ike4096 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
                            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
                            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
                            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
                            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'.
                            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
                            '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64'.
                            'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'.
                            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B'.
                            'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'.
                            'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31'.
                            '43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'.
                            '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA'.
                            '2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6'.
                            '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED'.
                            '1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'.
                            '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199'.
                            'FFFFFFFFFFFFFFFF'
  },
  ike6144 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
                            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
                            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
                            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
                            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'.
                            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
                            '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64'.
                            'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'.
                            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B'.
                            'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'.
                            'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31'.
                            '43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'.
                            '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA'.
                            '2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6'.
                            '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED'.
                            '1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'.
                            '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492'.
                            '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD'.
                            'F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831'.
                            '179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B'.
                            'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF'.
                            '5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6'.
                            'D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3'.
                            '23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA'.
                            'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328'.
                            '06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C'.
                            'DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE'.
                            '12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF'
  },
  ike8192 => { g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'.
                            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'.
                            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'.
                            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'.
                            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'.
                            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'.
                            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'.
                            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'.
                            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'.
                            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'.
                            '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64'.
                            'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'.
                            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B'.
                            'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'.
                            'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31'.
                            '43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'.
                            '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA'.
                            '2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6'.
                            '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED'.
                            '1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'.
                            '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492'.
                            '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD'.
                            'F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831'.
                            '179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B'.
                            'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF'.
                            '5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6'.
                            'D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3'.
                            '23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA'.
                            'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328'.
                            '06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C'.
                            'DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE'.
                            '12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4'.
                            '38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300'.
                            '741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568'.
                            '3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9'.
                            '22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B'.
                            '4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A'.
                            '062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36'.
                            '4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1'.
                            'B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92'.
                            '4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47'.
                            '9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71'.
                            '60C980DD98EDD3DFFFFFFFFFFFFFFFFF'
  }
);

sub new {
  my ($class, $f) = @_;
  my $self = _new();
  $self->import_key($f) if $f;
  return  $self;
}

sub import_key {
  my ($self, $key) = @_;
  croak "FATAL: undefined key" unless $key;
  my $data;
  if (ref($key) eq 'SCALAR') {
    $data = $$key;
  }
  elsif (-f $key) {
    $data = read_rawfile($key);
  }
  else {
    croak "FATAL: non-existing file '$key'";
  }
  croak "FATAL: invalid key format" unless $data;
  return $self->_import($data);
}

sub import_key_raw {
  my ($self, $raw_bytes, $type, $param) = @_;
  my ($g, $p, $x, $y);

  if (ref $param eq 'HASH') {
    $g = $param->{g} or croak "FATAL: 'g' param not specified";
    $p = $param->{p} or croak "FATAL: 'p' param not specified";
    $g =~ s/^0x//;
    $p =~ s/^0x//;
  } elsif (my $dhparam = $DH_PARAMS{$param}) {
    $g = $dhparam->{g};
    $p = $dhparam->{p};
  } else {
    croak "FATAL: invalid parameter";
  }

  if ($type eq 'private') {
    $type = 1;
  } elsif ($type eq 'public') {
    $type = 0;
  } else {
    croak "FATAL: invalid key type '$type'";
  }
  my $rv = $self->_import_raw($raw_bytes, $type, $g, $p);
  croak "FATAL: invalid public key" unless $self->_is_pubkey_valid;
  return $rv;
}

sub encrypt {
  my ($self, $data, $hash_name) = @_;
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');
  return $self->_encrypt($data, $hash_name);
}

sub decrypt {
  my ($self, $data) = @_;
  return $self->_decrypt($data);
}

sub sign_message {
  my ($self, $data, $hash_name) = @_;
  $hash_name ||= 'SHA1';
  my $data_hash = digest_data($hash_name, $data);
  return $self->_sign($data_hash);
}

sub verify_message {
  my ($self, $sig, $data, $hash_name) = @_;
  $hash_name ||= 'SHA1';
  my $data_hash = digest_data($hash_name, $data);
  return $self->_verify($sig, $data_hash);
}

sub sign_hash {
  my ($self, $data_hash) = @_;
  return $self->_sign($data_hash);
}

sub verify_hash {
  my ($self, $sig, $data_hash) = @_;
  return $self->_verify($sig, $data_hash);
}

sub generate_key {
  my ($key,$param) = @_;

  if (!ref $param) {
    if (my $dhparam = $DH_PARAMS{$param}) {
      $param = $dhparam;
    } else {
      croak "FATAL: invalid key length" unless ($param >= 96 || $param <= 512);
      return $key->_generate_key($param);
    }
  }
  my $g = $param->{g} or croak "FATAL: 'g' param not specified";
  my $p = $param->{p} or croak "FATAL: 'p' param not specified";
  $g =~ s/^0x//;
  $p =~ s/^0x//;
  return $key->_generate_key_ex($g, $p);
}

### FUNCTIONS

sub dh_encrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub dh_decrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->decrypt(@_);
}

sub dh_sign_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_message(@_);
}

sub dh_verify_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_message(@_);
}

sub dh_sign_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_hash(@_);
}

sub dh_verify_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_hash(@_);
}

sub dh_shared_secret {
  my ($privkey, $pubkey) = @_;
  $privkey = __PACKAGE__->new($privkey) unless ref $privkey;
  $pubkey  = __PACKAGE__->new($pubkey)  unless ref $pubkey;
  carp "FATAL: invalid 'privkey' param" unless ref($privkey) eq __PACKAGE__ && $privkey->is_private;
  carp "FATAL: invalid 'pubkey' param"  unless ref($pubkey)  eq __PACKAGE__;
  return $privkey->shared_secret($pubkey);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::DH - Public key cryptography based on Diffie-Hellman

=head1 SYNOPSIS

 ### OO interface

 #Encryption: Alice
 my $pub = Crypt::PK::DH->new('Bob_pub_dh1.key');
 my $ct = $pub->encrypt("secret message");
 #
 #Encryption: Bob (received ciphertext $ct)
 my $priv = Crypt::PK::DH->new('Bob_priv_dh1.key');
 my $pt = $priv->decrypt($ct);

 #Signature: Alice
 my $priv = Crypt::PK::DH->new('Alice_priv_dh1.key');
 my $sig = $priv->sign_message($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::DH->new('Alice_pub_dh1.key');
 $pub->verify_message($sig, $message) or die "ERROR";

 #Shared secret
 my $priv = Crypt::PK::DH->new('Alice_priv_dh1.key');
 my $pub = Crypt::PK::DH->new('Bob_pub_dh1.key');
 my $shared_secret = $priv->shared_secret($pub);

 #Key generation
 my $pk = Crypt::PK::DH->new();
 $pk->generate_key(128);
 my $private = $pk->export_key('private');
 my $public = $pk->export_key('public');

 or

 my $pk = Crypt::PK::DH->new();
 $pk->generate_key('ike2048');
 my $private = $pk->export_key('private');
 my $public = $pk->export_key('public');

 or

 my $pk = Crypt::PK::DH->new();
 $pk->generate_key({ p => $p, g => $g });
 my $private = $pk->export_key('private');
 my $public = $pk->export_key('public');

 ### Functional interface

 #Encryption: Alice
 my $ct = dh_encrypt('Bob_pub_dh1.key', "secret message");
 #Encryption: Bob (received ciphertext $ct)
 my $pt = dh_decrypt('Bob_priv_dh1.key', $ct);

 #Signature: Alice
 my $sig = dh_sign_message('Alice_priv_dh1.key', $message);
 #Signature: Bob (received $message + $sig)
 dh_verify_message('Alice_pub_dh1.key', $sig, $message) or die "ERROR";

 #Shared secret
 my $shared_secret = dh_shared_secret('Alice_priv_dh1.key', 'Bob_pub_dh1.key');

=head1 METHODS

=head2 new

  my $pk = Crypt::PK::DH->new();
  #or
  my $pk = Crypt::PK::DH->new($priv_or_pub_key_filename);
  #or
  my $pk = Crypt::PK::DH->new(\$buffer_containing_priv_or_pub_key);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key($keysize);
 ### $keysize (in bytes) corresponds to DH params (p, g) predefined by libtomcrypt
 # 96   =>  DH-768
 # 128  =>  DH-1024
 # 160  =>  DH-1280
 # 192  =>  DH-1536
 # 224  =>  DH-1792
 # 256  =>  DH-2048
 # 320  =>  DH-2560
 # 384  =>  DH-3072
 # 512  =>  DH-4096

The following variants are available since CryptX-0.032

 $pk->generate_key($name)
 ### $name corresponds to values defined in RFC7296 and RFC3526
 # ike768  =>  768-bit MODP (Group 1)
 # ike1024 => 1024-bit MODP (Group 2)
 # ike1536 => 1536-bit MODP (Group 5)
 # ike2048 => 2048-bit MODP (Group 14)
 # ike3072 => 3072-bit MODP (Group 15)
 # ike4096 => 4096-bit MODP (Group 16)
 # ike6144 => 6144-bit MODP (Group 17)
 # ike8192 => 8192-bit MODP (Group 18)

 $pk->generate_key($param_hash)
 ## $param_hash is { g => $g, p => $p }
 ## where $g is the generator (base) in a hex string and $p is the prime in a hex string

=head2 import_key

Loads private or public key (exported by L</export_key>).

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

=head2 import_key_raw

I<Since: CryptX-0.032>

  $pk->import_key_raw($raw_bytes, $type, $params)
  ### $raw_bytes is a binary string containing the key
  ### $type is either 'private' or 'public'
  ### $param is either a name ('ike2038') or hash containing the p,g values { g=>$g, p=>$p }
  ### in hex strings

=head2 export_key

 my $private = $pk->export_key('private');
 #or
 my $public = $pk->export_key('public');

=head2 export_key_raw

I<Since: CryptX-0.032>

 $raw_bytes = $dh->export_key_raw('public')
 #or
 $raw_bytes = $dh->export_key_raw('private')

=head2 encrypt

 my $pk = Crypt::PK::DH->new($pub_key_filename);
 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 decrypt

 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $pt = $pk->decrypt($ciphertext);

=head2 sign_message

 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $signature = $priv->sign_message($message);
 #or
 my $signature = $priv->sign_message($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 verify_message

 my $pk = Crypt::PK::DH->new($pub_key_filename);
 my $valid = $pub->verify_message($signature, $message)
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 sign_hash

 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $signature = $priv->sign_hash($message_hash);

=head2 verify_hash

 my $pk = Crypt::PK::DH->new($pub_key_filename);
 my $valid = $pub->verify_hash($signature, $message_hash);

=head2 shared_secret

 # Alice having her priv key $pk and Bob's public key $pkb
 my $pk  = Crypt::PK::DH->new($priv_key_filename);
 my $pkb = Crypt::PK::DH->new($pub_key_filename);
 my $shared_secret = $pk->shared_secret($pkb);

 # Bob having his priv key $pk and Alice's public key $pka
 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $pka = Crypt::PK::DH->new($pub_key_filename);
 my $shared_secret = $pk->shared_secret($pka);  # same value as computed by Alice

=head2 is_private

 my $rv = $pk->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 size

 my $size = $pk->size;
 # returns key size in bytes or undef if no key loaded

=head2 key2hash

 my $hash = $pk->key2hash;

 # returns hash like this (or undef if no key loaded):
 {
   type => 0,   # integer: 1 .. private, 0 .. public
   size => 256, # integer: key size in bytes
   x => "FBC1062F73B9A17BB8473A2F5A074911FA7F20D28FB...", #private key
   y => "AB9AAA40774D3CD476B52F82E7EE2D8A8D40CD88BF4...", #public key
   g => "2", # generator/base
   p => "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80D...", # prime
}

=head2 params2hash

I<Since: CryptX-0.032>

 my $params = $pk->params2hash;

 # returns hash like this (or undef if no key loaded):
 {
   g => "2", # generator/base
   p => "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80D...", # prime
}

=head1 FUNCTIONS

=head2 dh_encrypt

DH based encryption as implemented by libtomcrypt. See method L</encrypt> below.

 my $ct = dh_encrypt($pub_key_filename, $message);
 #or
 my $ct = dh_encrypt(\$buffer_containing_pub_key, $message);
 #or
 my $ct = dh_encrypt($pub_key_filename, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

Encryption works similar to the L<Crypt::PK::ECC> encryption whereas shared DH key is computed, and
the hash of the shared key XOR'ed against the plaintext forms the ciphertext.

=head2 dh_decrypt

DH based decryption as implemented by libtomcrypt. See method L</decrypt> below.

 my $pt = dh_decrypt($priv_key_filename, $ciphertext);
 #or
 my $pt = dh_decrypt(\$buffer_containing_priv_key, $ciphertext);

=head2 dh_sign_message

Generate DH signature as implemented by libtomcrypt. See method L</sign_message> below.

 my $sig = dh_sign_message($priv_key_filename, $message);
 #or
 my $sig = dh_sign_message(\$buffer_containing_priv_key, $message);
 #or
 my $sig = dh_sign_message($priv_key, $message, $hash_name);

=head2 dh_verify_message

Verify DH signature as implemented by libtomcrypt. See method L</verify_message> below.

 dh_verify_message($pub_key_filename, $signature, $message) or die "ERROR";
 #or
 dh_verify_message(\$buffer_containing_pub_key, $signature, $message) or die "ERROR";
 #or
 dh_verify_message($pub_key, $signature, $message, $hash_name) or die "ERROR";

=head2 dh_sign_hash

Generate DH signature as implemented by libtomcrypt. See method L</sign_hash> below.

 my $sig = dh_sign_hash($priv_key_filename, $message_hash);
 #or
 my $sig = dh_sign_hash(\$buffer_containing_priv_key, $message_hash);

=head2 dh_verify_hash

Verify DH signature as implemented by libtomcrypt. See method L</verify_hash> below.

 dh_verify_hash($pub_key_filename, $signature, $message_hash) or die "ERROR";
 #or
 dh_verify_hash(\$buffer_containing_pub_key, $signature, $message_hash) or die "ERROR";

=head2 dh_shared_secret

DH based shared secret generation. See method L</shared_secret> below.

 #on Alice side
 my $shared_secret = dh_shared_secret('Alice_priv_dh1.key', 'Bob_pub_dh1.key');

 #on Bob side
 my $shared_secret = dh_shared_secret('Bob_priv_dh1.key', 'Alice_pub_dh1.key');

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange|https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange>

=back
