# NAME

Crypt::ARIA - Perl extension for ARIA encryption/decryption algorithm.

# VERSION

version 0.005

# SYNOPSIS

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
    my $cipher    = $aria->encrypt_ecb( $plain );
    my $decrypted = $aria->decrypt_ecb( $cipher );
    # note that $decrypt may not be same as $plain, because it is appended
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
    my $plain  = $cbc->decrypt( $cipher );

# DESCRIPTION

Crypt::ARIA provides an interface between Perl and ARIA implementation
in C.

ARIA is a block cipher algorithm designed in South Korea.
For more information about ARIA, visit links in ["SEE ALSO"](#see-also) section.

The C portion of this module is made by researchers of ARIA and is
available from the ARIA website. I had asked them and they've made sure
that the code is free to use.

# METHODS

- new

    `new()` method creates an object.

        my $aria = Crypt::ARIA->new();

    You can give a master key as argument. The master key in ARIA should be of 16, 24, or 32 bytes.

        my $key = pack 'H*', '00112233445566778899aabbccddeeff';
        my $aria = Crypt::ARIA->new( $key );

- set\_key

    `set_key()` sets a master key. This method returns the object itself.

        $aria->set_key( pack 'H*', '00112233445566778899aabbccddeeff' );

- set\_key\_hexstring

    `set_key_hexstring()` sets a master key. You can give a hexstring as
    argument. The hexstring can include whitespaces.
    This method returns the object itself.

        $aria->set_key_hexstring( '00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff' );

- unset\_key

    This method removes the master key from object and return the object itsetf.

        $aria->unset_key();

- has\_key

    This method returns true if a master key is set, false otherwise.

- encrypt

    `encrypt()` encrypts a block of plaintext.

        my $cipher = $aria->encrypt( $plain );

    $plain should be of exactly 16 bytes.
    It returns a ciphertext of 16 bytes.
    If you want to encrypt a text of different length,
    you have to choose the operation mode and the padding method.
    You may implement them by yourself or use another module for them.

    `Crypt::ARIA` is designed to be compatible with [Crypt::CBC](https://metacpan.org/pod/Crypt::CBC).
    Therefore, you can use `Crypt::CBC` to use CBC mode with several
    padding methods.

        use Crypt::CBC;
        my $cbc = Crypt::CBC->new(
              -cipher => Crypt::ARIA->new()->set_key( $key ),
              -iv     => $initial_vector,
              -header => 'none';
              -padding => 'none';
          );
        my $cipher = $cbc->encrypt( $plain );
        my $plain  = $cbc->decrypt( $cipher );

- decrypt

    `decrypt()` decrypts a block of ciphertext.

        my $plain  = $aria->decrypt( $cipher );

    $cipher should be of exactly 16 bytes.
    Again, you have to use another module to decrypt multi-block
    message.

- encrypt\_ecb

    This method encrypts a plaintext of arbitrary length.

        my $cipher  = $aria->encrypt_ecb( $plain );

    It returns the ciphertext whose length is multiple of 16 bytes.

    NOTE: If the length of $plain is not n-times of 16 exactly,
    `encrypt_ecb()` appends null bytes to fill it. If the length
    is n-times of 16 exactly, $plain would be untouched. This means
    you should have to deliver the original length of $plain to the
    receiver. You had better use other module like [Crypt::CBC](https://metacpan.org/pod/Crypt::CBC) that
    provides advanced operation mode and padding method.
    This method is just for test purpose.

- decrypt\_ecb

    This method decrypts a multi-block ciphertext.

        my $decrypted = $aria->decrypt_ecb( $cipher );

    As described in ["encrypt_ecb"](#encrypt_ecb), $decrypted may contain a sequence
    of null bytes in its end. You should remove them yourself.

# SEE ALSO

[Crypt::CBC](https://metacpan.org/pod/Crypt::CBC), [Crypt::SEED](https://metacpan.org/pod/Crypt::SEED)

[http://en.wikipedia.org/wiki/ARIA_%28cipher%29](http://en.wikipedia.org/wiki/ARIA_%28cipher%29)

[http://210.104.33.10/ARIA/index-e.html](http://210.104.33.10/ARIA/index-e.html)

IETF RFC 5794 : A Description of the ARIA Encryption Algorithm
[http://tools.ietf.org/html/rfc5794](http://tools.ietf.org/html/rfc5794)

# AUTHOR

Geunyoung Park <gypark@gmail.com>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by Geunyoung Park.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
