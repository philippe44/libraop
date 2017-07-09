package Data::Plist::Foundation::NSObject;

use strict;
use warnings;
use Class::ISA;
use UNIVERSAL::isa;
use Scalar::Util qw//;

sub init {
    my $self = shift;
}

sub replacement {
    my $self = shift;
    $self->init;
    return $self;
}

sub serialize_class {
    my $self = shift;
    $self = ref $self if ref $self;

    my $short = $self;
    $short =~ s/^Data::Plist::Foundation:://;
    return [
        UID => [
            dict => {
                '$classes' => [
                    array => [
                        map { s/^Data::Plist::Foundation:://; [ string => $_ ] }
                            grep { $_->isa("Data::Plist::Foundation::NSObject") }
                            Class::ISA::self_and_super_path($self)
                    ]
                ],
                '$classname' => [ string => $short ],
            }
        ]
    ];
}

sub serialize_equiv {
    my $self = shift;
    return { %{$self} };
}

sub serialize {
    my $self = shift;
    my %dict;
    $dict{'$class'} = $self->serialize_class;
    my $equiv = $self->serialize_equiv;
    for my $key ( keys %{$equiv} ) {
        my $value = Data::Plist::Writer->serialize_value( $equiv->{$key} );
        if ( $value->[0] =~ /^(data|integer|real|true|false)$/ ) {
            $dict{$key} = $value;
        } else {
            $dict{$key} = [ UID => $value ];
        }
    }
    return [ dict => \%dict ];
}

1;
