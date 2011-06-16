#mod_amend

amend request url

## Installation

    apxs -cia mod_amend.c

## Configuration
write to outside <Directory> or <Location> on *.conf  

    AmendSkip /skip_from/ /skip_to/
    AmendQuery /query_from/ /query_to/ query_separator

**special characters**  
    '^' means the beginning of a url for AmendSkip configuration  
    '$' means the end of url for AmendQuery configuration  

**for example**  
if you want to use amazon.com like;  

    http://www.amazon.com/Little-Bets-Breakthrough-Emerge-Discoveries/dp/1439170428

configure to:

    AmendSkip ^ /dp/
    AmendQuery /dp/ $ /

that convert url to:

    http://www.amazon.com/?1439170428
