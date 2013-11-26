use strict;
use warnings;
package Crypt::ARIA;

use Carp qw/croak carp/;

# ABSTRACT: Perl extension for ARIA encryption/decryption algorithm.

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration   use Crypt::ARIA ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

# our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Crypt::ARIA', $Crypt::ARIA::VERSION);

# Preloaded methods go here.

use constant BLOCKSIZE => 16;
use constant KEYSIZES => ( 128, 192, 256 );
use constant MAX_USER_KEYS => 99_999_999;

sub blocksize { return BLOCKSIZE; }
sub keysize     { return max_keysize(); }
sub max_keysize { return (KEYSIZES)[-1] / 8; }
sub min_keysize { return (KEYSIZES)[0] / 8;  }

sub usage {
    my ( $package, $filename, $line, $subr ) = caller(1);
    $Carp::CarpLevel = 2;
    croak "Usage: $subr(@_)";
}

# new( [ key ] )
sub new {
    my $this = shift;
    my $class = ref($this) || $this;

    my $self = { };
    bless $self, $class;

    if ( @_ ) {
        $self->set_key( shift );
    }

    return $self;
}

sub has_key {
    my $self = shift;

    return defined( $self->{key} );
}

sub set_key {
    my $self = shift;
    my $key  = shift;

    my $len  = 8 * length $key;
    unless ( grep { $len == $_ } KEYSIZES ) {
        croak 'Keysize should be one of '.join(',', KEYSIZES).' bits.'
             .'(current keysize = '.$len.' bits)';
    }
    $self->{key} = $key;
    $self->{keybits} = 8 * length $key;

    ( $self->{enc_round}, $self->{enc_roundkey} ) = _setup_enc_key( $self->{key}, $self->{keybits} );
    ( $self->{dec_round}, $self->{dec_roundkey} ) = _setup_dec_key( $self->{key}, $self->{keybits} );
}

sub set_key_hexstring {
    my $self = shift;
    my $key  = shift;

    $key =~ s/\s+//g;
    $self->set_key( pack("H*", $key) );

    return $self;
}

sub unset_key {
    my $self = shift;

    undef $self->{key};
    undef $self->{enc_round};
    undef $self->{enc_roundkey};
    undef $self->{dec_round};
    undef $self->{dec_roundkey};

    return $self;
}

# one block
sub encrypt {
    my $self = shift;
    my $data = shift;

    unless ( defined $self->{enc_roundkey} and defined $self->{enc_round} ) {
        carp 'key should be provided using set_key() or set_key_hexstring().';
        return undef;
    }

    my $len = length $data;
    if ( $len != BLOCKSIZE ) {
        carp 'data should be '.BLOCKSIZE.' bytes.';
        return undef;
    }

    my $cipher = _crypt( $data, $self->{enc_round}, $self->{enc_roundkey} );
    return $cipher;
}

sub decrypt {
    my $self   = shift;
    my $cipher = shift;

    unless ( defined $self->{enc_roundkey} and defined $self->{enc_round} ) {
        carp 'key should be provided using set_key() or set_key_hexstring().';
        return undef;
    }

    my $len = length $cipher;
    if ( $len != BLOCKSIZE ) {
        carp 'cipher should be '.BLOCKSIZE.' bytes.';
        return undef;
    }

    my $data = _crypt( $cipher, $self->{dec_round}, $self->{dec_roundkey} );
    return $data;
}

# ECB - null padding
sub encrypt_ecb {
    my $self = shift;
    my $data = shift;

    my $len = length $data;
    my $cipher = "";

    my $i = 0;
    while ( $i < $len ) {
        my $buflen = ($len-$i) > BLOCKSIZE ? BLOCKSIZE : $len - $i;
        my $buf = substr( $data, $i, $buflen );
        if ( $buflen < BLOCKSIZE ) {
            $buf .= "\x00" x (BLOCKSIZE - $buflen);
        }
        my $cipbuf = $self->encrypt( $buf );
        $cipher .= $cipbuf;
        $i += $buflen;
    }

    return $cipher;
}

sub decrypt_ecb {
    my $self   = shift;
    my $cipher = shift;

    my $len = length $cipher;
    if ( $len % BLOCKSIZE ) {
        carp 'Size of cipher is not a multiple of '.BLOCKSIZE;
        return undef;
    }

    my $data = "";

    my $i = 0;
    while ( $i < $len ) {
        my $cipbuf = substr( $cipher, $i, BLOCKSIZE );
        my $buf = $self->decrypt( $cipbuf );
        $data .= $buf;
        $i += BLOCKSIZE;
    }

    return $data;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!


=head1 SYNOPSIS

  use Crypt::ARIA;

  # create an object
  my $aria = Crypt::ARIA->new();
  # or,
  my $key = pack 'H*', '00112233445566778899aabbccddeeff';
  my $aria = Crypt::ARIA->new( $key );


  # set master key
  $aria->set_key( pack 'H*', '00112233445566778899aabbccddeeff' );
  # or
  # (whitespace allowed)
  $aria->set_key_hexstring( '00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff' );


  # one block encryption/decryption
  # $plaintext and $ciphertext should be of "blocksize()" bytes.
  my $cipher = $aria->encrypt( $plain );
  my $plain  = $aria->decrypt( $cipher );

  
  # multi block encryption/decryption
  # simple ECB mode
  my $cipher  = $aria->encrypt_ecb( $plain );
  my $decrypt = $aria->decrypt_ecb( $cipher );
  # note that $decrypt may not same as $plain, because it is appended
  # null bytes to.


  # CBC mode
  use Crypt::CBC;
  my $cbc = Crypt::CBC->new(
        -cipher => Crypt::ARIA->new()->set_key( $key ),
        -iv     => $initial_vector,
        -header => 'none';
        -padding => 'none';
    );
  my $cipher = $cbc->encrypt( $plain );
  my $plain  = $cbc->default( $cipher );


=head1 DESCRIPTION

blah blah blah

=head1 EXPORT

None by default.

=head1 SEE ALSO

L<Crypt::CBC>, L<Crypt::SEED>

L<http://en.wikipedia.org/wiki/ARIA_%28cipher%29>

L<http://210.104.33.10/ARIA/index-e.html>

IETF RFC 5794 : A Description of the ARIA Encryption Algorithm
L<http://tools.ietf.org/html/rfc5794>


=cut
