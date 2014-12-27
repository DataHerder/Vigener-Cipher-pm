#!/usr/bin/perl

use VigenerCipher;

use strict;
use warnings;

my $encrypt_value = "Encrypt this.";
my $Vig = new VigenerCipher('this is the key');
$Vig->validate($encrypt_value) || die $!;
my $encryption = $Vig->encrypt('encrypt this string');
my $decrypt = $Vig->decrypt($encryption);

print "Encrypted: ".$encryption."\n";
print "Decrypted: ".$decrypt;