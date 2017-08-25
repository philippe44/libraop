use strict;
use strict;

use lib './lib';

use File::Spec::Functions;
use Data::Dumper;
use LWP::Simple;
use LWP;
use Data::Plist::BinaryWriter;
use Data::Plist::BinaryReader;
use feature qw(say);
use Crypt::SRP;
use Math::BigInt;
use Crypt::Digest::SHA512 qw (sha512);
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::Ed25519;
use Crypt::Curve25519;
use Crypt::Mode::CTR;
use Encode qw(decode encode);

my $force  = 0;

#replace with your AppleTV IP address
my $host = 'http://192.168.2.49:7000';

sub step {
	my ($ua, $url, $param) = @_;
	my $req = HTTP::Request->new(POST => $url);
	
	return if $force;
	
	$req->header('Content-Type' => 'application/x-apple-binary-plist');
	# there was something strange with UA when set to itunes 12.x.y but can't remember what
	# $req->header('User-Agent' => 'iTunes/4.7.1 (Windows; N; Windows 7; 8664; EN; cp1252) SqueezeCenter, Squeezebox Server, Logitech Media Server');
	
	if (defined $param) {
		my $bplist = Data::Plist::BinaryWriter->new;
		$req->content($bplist->write($param));			 
	}	
	
	my $res = $ua->request($req);
	#say Dumper($res);
	return undef if !$res->content;
		
	my $bplist = Data::Plist::BinaryReader->new;
	my $data = $bplist->open_string($res->content)->data;	
	#say Dumper($data);
	
	return $data;
}

my $client_id = uc(unpack('H*', Crypt::PRNG::random_bytes(8)));
$client_id = '366B4165DD64AD3A' if ($force);
say ("<ID>    :", $client_id);

my $data;
my $param;
my $ua = LWP::UserAgent->new(keep_alive => 1);
$ua->timeout(2);

# step 0)
say "step ... 0";
step($ua, "$host/pair-pin-start");

# step 1)
say "step ... 1";
$param = { 'method' => 'pin', 'user' => $client_id};
$data = step($ua, "$host/pair-setup-pin", $param);

# step 2)
say "step ... 2";
my $client = Crypt::SRP->new('RFC5054-2048bit', 'SHA1');
my $pin;

if ($force) {
	$data->{pk} = Crypt::SRP::_bignum2bytes(Math::BigInt->new('0x4223ddb35967419ddfece40d6b552b797140129c1c262da1b83d413a7f9674aff834171336dabadf9faa95962331e44838d5f66c46649d583ee44827755651215dcd5881056f7fd7d6445b844ccc5793cc3bbd5887029a5abef8b173a3ad8f81326435e9d49818275734ef483b2541f4e2b99b838164ad5fe4a7cae40599fa41bd0e72cb5495bdd5189805da44b7df9b7ed29af326bb526725c2b1f4115f9d91e41638876eeb1db26ef6aed5373f72e3907cc72997ee9132a0dcafda24115730c9db904acbed6d81dc4b02200a5f5281bf321d5a3216a709191ce6ad36d383e79be76e37a2ed7082007c51717e099e7bedd7387c3f82a916d6aca2eb2b6ff3f3'));
	$data->{salt} = Crypt::SRP::_bignum2bytes(Math::BigInt->new('0xd62c98fe76c77ad445828c33063fc36f'));
	$client->{predefined_a} = Math::BigInt->new('0xa18b940d3e1302e932a64defccf560a0714b3fa2683bbe3cea808b3abfa58b7d');
	$pin = '1234';
} 

my ($A, $a) = $client->client_compute_A(32);
my $a_public = Crypt::Ed25519::eddsa_public_key($a);
say "<pk>    :", unpack("H*", $data->{pk});
say "<salt>  :", unpack("H*", $data->{salt});
say "<A>     :", unpack("H*", $A);
say "<a>     :", unpack("H*", $a);
say "<a_pub> :", unpack("H*", $a_public);
exit if !$client->client_verify_B($data->{pk});

if (!$force) {
	print "enter PIN: ";
	$pin = <STDIN>;
	chomp($pin);
}	

$client->client_init($client_id, $pin, $data->{salt});
my $M1 = $client->client_compute_M1;
say "<M1>    :", unpack("H*", $M1);

$param = { 'pk' => $A, 'proof' => $M1 };
$data = step($ua, "$host/pair-setup-pin", $param);

#exit if !$client->client_verify_M2($data->{proof});
my $K = $client->get_secret_K;
say "<K>     :", unpack("H*", $K);

# step 3)
say "step ... 3";
my $sha = Crypt::Digest::SHA512->new;

$sha->add( encode('UTF-8','Pair-Setup-AES-Key') );
$sha->add( $K );
my $aes_key = substr($sha->digest, 0, 16);
say "<aes_key>     :", unpack("H*", $aes_key);

$sha->reset;
$sha->add( encode('UTF-8','Pair-Setup-AES-IV') );
$sha->add( $K );
my $aes_iv = substr($sha->digest, 0, 16);
substr($aes_iv, -1, 1) = pack('C', unpack('C', substr($aes_iv, -1, 1)) + 1);
say "<aes_iv>      :", unpack("H*", $aes_iv);

my ($epk, $tag) = gcm_encrypt_authenticate('AES', $aes_key, $aes_iv, '', $a_public);
say "<epk>         :", unpack("H*", $epk);
say "<tag>         :", unpack("H*", $tag);

$param = { 'epk' => $epk, 'authTag' => $tag };
$data = step($ua, "$host/pair-setup-pin", $param);

if (defined $data) {
	say "SUCCESS";
} else {
	say "FAILED";	
}

my $credentials = $client_id . ":" . unpack("H*", $a);
say "credentials   :", $credentials;

# ============================= VERIFICATION ===================================

# verification 1)
my ($client_id, $a) = split(/:/, $credentials);
$a = pack("H*", $a);
my $a_public = Crypt::Ed25519::eddsa_public_key($a);
say "a_pub         :", unpack("H*", $a_public);

say "verify ... 1";
my $verifier = Crypt::Curve25519->new();
my $verify_secret_hex;
if ($force) {
	$verify_secret_hex = $verifier->secret_key( unpack('H*', $a ) );
} else {
	$verify_secret_hex = $verifier->secret_key( unpack('H*', Crypt::PRNG::random_bytes(32)) );
}

my $verify_public = pack("H*", $verifier->public_key( $verify_secret_hex ));
say "verify_pub    :", unpack("H*", $verify_public);

my $req = HTTP::Request->new(POST => "$host/pair-verify");
$req->header('Content-Type' => 'application/octet-stream');
$req->content("\x01\x00\x00\x00" . $verify_public . $a_public );			 
my $res = $ua->request($req);
#say Dumper($res);

$data = $res->content;
if ($force) {
	$data = pack("H*", 'd62c8c9548d836736978ad4d426df3495192407bbbb9466c9970794cdd2fe43a3067a3ea868ade5c9fab43a8d5dc4d53ca1115dbf1c882888f877e85b65c3a82a61583f24c33bf0b9a6ec5c4ab2ecc555a939e7633557453854795e82f2d7ef6');
}	

my $atv_public = substr($data, 0, 32);
my $atv_data = substr($data, 32);
say "atv_public    :", unpack("H*", $atv_public);
say "atv_data      :", unpack("H*", $atv_data);

# verification 2)
say "verify ... 2";

my $shared_secret = pack("H*", $verifier->shared_secret( $verify_secret_hex, unpack("H*", $atv_public)));
say "shared_secret :", unpack("H*", $shared_secret);

my $sha = Crypt::Digest::SHA512->new;

$sha->add( encode('UTF-8','Pair-Verify-AES-Key') );
$sha->add( $shared_secret );
my $aes_key = substr($sha->digest, 0, 16);
say "aes_key       :", unpack("H*", $aes_key);

$sha->reset;
$sha->add( encode('UTF-8','Pair-Verify-AES-IV') );
$sha->add( $shared_secret );
my $aes_iv = substr($sha->digest, 0, 16);
say "aes_iv        :", unpack("H*", $aes_iv);

my $signed = Crypt::Ed25519::eddsa_sign($verify_public . $atv_public, $a_public, $a);
#say "buf: ", unpack("H*", $verify_public . $atv_public);
say "signed        :", unpack("H*", $signed);

my $m = Crypt::Mode::CTR->new('AES', 1);
$m->start_encrypt($aes_key, $aes_iv);
$m->add($atv_data);
my $signature = $m->add($signed);
$signature = "\x00\x00\x00\x00" . $signature; 
say "signature     :", unpack("H*", $signature);

my $req = HTTP::Request->new(POST => "$host/pair-verify");
$req->header('Content-Type' => 'application/octet-stream');
$req->content($signature);			 
my $res = $ua->request($req);

if ($res->is_success) {
	say "VERIFIED";
} else {
	say "FAILED";	
}	


