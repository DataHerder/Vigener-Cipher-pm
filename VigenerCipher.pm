#!/usr/bin/perl

##############
# just a simple vigener cipher written in Perl
#
# encrypts a string using the ASCII table and a key,
# as long as you have the key, you can decrypt vigener cipher
# using this package
# useage in test-vigener.pl

package VigenerCipher;

use strict;
use warnings;

sub new
{
	my $class = shift;
	my $key = shift;
	my $custom = shift;
	my $self = {};

	# escape these characters for PCRE regex flavor
	my $regex = join('', map {'\\'.$_} split //, '.^$*+?()[]{\|');

	{
		no warnings 'uninitialized';
		if (length($custom) >= 1) {
			for ( 0 .. length($custom) - 1 ) {
				my $chr = substr($custom, $_, 1);
				if ($chr =~ /[$regex]/) {
					$self->{_special} .= $chr;
				} else {
					$self->{_useable} .= $chr;
				}
			}
		} else {
			for (my $i = 32; $i <= 254; $i++) {
				my $chr = chr($i);
				if ($chr =~ /[$regex]/) {
					$self->{_special} .= $chr;
				} else {
					$self->{_useable} .= $chr;
				}
			}
		}
	}

	$self->{_key} = $key;
	$self->{_total_c} = length($self->{_useable}) + length($self->{_special});
	#print $self->{_total_c};die;
	$self->{_fullstring} = $self->{_useable} . $self->{_special};

	my %key_map = (); my $last = 0;
	for ( 0 .. length($self->{_fullstring}) - 1 ) {
		$key_map{substr($self->{_fullstring}, $_, 1)} = $_;
	}
	$self->{_map} = \%key_map;
	bless $self, $class;
	return $self;
}

sub setKey
{
	# reset the key
	my $self = shift;
	my $key = shift;

	{
		no warnings 'uninitialized';
		if (length($key) == 0) {
			$@ = 'The key is not set.';
			return undef;
		}
	}

	$self->{_key} = $key;
	return 1;
}

sub validate
{
	my $self = shift;
	my $string_to_validate = shift;

	{
		no warnings 'uninitialized';
		if (length($string_to_validate) == 0) {
			$@ = 'Nothing to validate.';
			return undef;
		}
	}

	my $reg = '^['.join('', $self->{_useable}).join('', map { ($_ =~ /\n/) ? '\n' : "\\".$_ } split //, $self->{_special}).']+$';

	if ($string_to_validate !~ /$reg/) {
		$@ = "Unsupported characters found in string.  Only ASCII characters are supported.";
		return undef;
	}
	
	return 1;
}

sub encrypt
{
	my $self = shift;
	my $string = shift;
	return $self->_encrypt_algo($string, 'encrypt');
}

sub decrypt
{
	my $self = shift;
	my $string = shift;
	return $self->_encrypt_algo($string, 'decrypt');
}

sub _encrypt_algo
{
	my $self = shift;
	my $string = shift;
	my $type = shift;
	my $validate = 1;
	my $change = 0;
	if ($self->validate($string)) {
		my $c = 0;
		my $encrypted_string = '';
		for ( 0 .. length($string)-1) {
			my $char = substr($string, $_, 1);
			my $a = $self->{_map}->{$char};
			my $b = $self->{_map}->{substr($self->{_key}, $c, 1)};
			if ($type eq 'encrypt') {
				$change = $a + $b;
				if ($change > $self->{_total_c}) {
					$change = $change - $self->{_total_c};
				}
				$encrypted_string.= substr($self->{_fullstring}, $change-1, 1);
			} elsif ($type eq 'decrypt') {
				$change = $a - $b;
				if ($change < 0) {
					$change = $self->{_total_c} - ($change * -1);
				}
				my $tmp = substr($self->{_fullstring}, $change+1, 1);
				if ($change + 1 == $self->{_total_c}) {
					$change = -1;
				}
				$encrypted_string.= substr($self->{_fullstring}, $change+1, 1);
			} else {
				$@ = "Encryption algo not specified.";
				return undef;
			}

			# go through the cypher with c, if we reach the end,
			# restart the counter
			$c++;
			if ($c == length($self->{_key})) {
				$c = 0;
			}
		}
		return $encrypted_string;
	}
	return '';
}


return 1;