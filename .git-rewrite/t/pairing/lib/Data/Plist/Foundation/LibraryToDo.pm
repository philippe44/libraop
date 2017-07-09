package Data::Plist::Foundation::LibraryToDo;

use strict;
use warnings;

use base qw/Data::Plist::Foundation::ToDo Class::Accessor/;

my %mapping = (
    alarms       => "ToDo Alarms",
    cal_id       => "ToDo Calendar ID",
    calendar     => "ToDo Calendar Title",
    complete     => "ToDo Completed",
    completed_at => "ToDo Date Completed",
    created      => "ToDo Date Created",
    due          => "ToDo Due Date",
    notes        => "ToDo Notes",
    priority     => "ToDo Priority",
    title        => "ToDo Title",
    url          => "ToDo URL",
    id           => "ToDo iCal ID",
    keys_digest  => "ToDo Keys Digest",
);

my %lookup = ( reverse %mapping );

sub init {
    my $self = shift;

    __PACKAGE__->mk_accessors( grep { not $self->can($_) } keys %mapping );
    $self->{ $lookup{$_} } = delete $self->{$_}
        for grep { exists $lookup{$_} } keys %{$self};

    $self->due(undef)      unless delete $self->{"ToDo Due Date Enabled"};
    $self->priority(undef) unless delete $self->{"ToDo Priority Enabled"};
}

sub serialize_equiv {
    my $self = shift;
    my $hash = {};
    $hash->{ $mapping{$_} } = $self->{$_} for keys %{$self};
    return $hash;
}

sub serialize {
    my $self = shift;
    my $ret  = $self->SUPER::serialize;
    $ret->[1]{"ToDo Completed"}
        = $self->{complete} ? [ true => 1 ] : [ false => 0 ];
    if ( $self->{due} ) {
        $ret->[1]{"ToDo Due Date Enabled"} = [ true => 1 ];
    } else {
        delete $ret->[1]{"ToDo Due Date"};
        $ret->[1]{"ToDo Due Date Enabled"} = [ false => 0 ];
    }

    if ( defined $self->{priority} ) {
        $ret->[1]{"ToDo Priority Enabled"} = [ true => 1 ];
    } else {
        $ret->[1]{"ToDo Priority"}         = [ integer => 1 ];
        $ret->[1]{"ToDo Priority Enabled"} = [ false   => 0 ];
    }

    return $ret;
}

1;
