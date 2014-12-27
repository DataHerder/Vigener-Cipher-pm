#!/usr/bin/perl
use VigenerCipher;

use strict;
use warnings;

my $encrypt_value = "Encrypt this.";
my $Vig = new VigenerCipher('this is the key');
$Vig->validate($encrypt_value) || die $!;
my $encryption = $Vig->encrypt('encrypt this string');
my $decryption = $Vig->decrypt($encryption);
print "Encrypted: ".$encryption."\n";
print "Decrypted: ".$decryption."\n";

# test the full range of possibilities
$Vig->setKey('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 !@#$%^&*()-_+={[}]|;:\'"<,>.?/~\`') || die $!;
$encryption = $Vig->encrypt('I was driving down the street yest3rday and th@re w&s a GREAT big mountain in my view with the s~ns3t``.');
$decryption = $Vig->decrypt($encryption);
print "Encrypted: ".$encryption."\n";
print "Decrypted: ".$decryption;
