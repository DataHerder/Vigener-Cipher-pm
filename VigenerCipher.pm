#!/usr/bin/perl

package VigenerCipher;

use strict;
use warnings;

sub new
{
	my $class = shift;
	my $self = {
		_key => shift,
		# these characters are used
		_useable => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 ',
		# special characters allowed
		_special => '!@#$%^&*()-_+={[}]|;:\'"<,>.?/~\`',
	};

	$self->{_total_c} = length($self->{_useable}) + length($self->{_special});
	$self->{_fullstring} = $self->{_useable} . $self->{_special};

	my %key_map = (); my $last = 0;
	for ( 0 .. length($self->{_fullstring}) - 1 ) {
		$key_map{substr($self->{_fullstring}, $_, 1)} = $_;
	}
	$self->{_map} = \%key_map;
	bless $self, $class;
	return $self;
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

	my $reg = '^[A-Za-z0-9\s'.join('', map { "\\".$_ } split //, $self->{_special}).']+$';

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