SubScanPy
======

SubScanPy - это сканер поддоменов DNS на основе списка слов на языке python.

Сначала скрипт попытается выполнить перенос зоны, используя каждый из серверов имен целевого домена.

Если это не удастся, программа выполнит поиск записей TXT и MX для домена, а затем выполнит рекурсивное сканирование поддомена, используя предоставленный список слов.

Usage
-----

SubScanPy.py (-d \<domain\> | -l \<list\>) [OPTIONS]

#### Mandatory Arguments
    -d  --domain                              Target domain; OR
    -l  --list                                Newline separated file of domains to scan
    
#### Optional Arguments
    -w --wordlist <wordlist>                  Wordlist of subdomains to use
    -t --threads <threadcount>                Threads (1 - 32), default 8
    -6 --ipv6                                 Scan for IPv6 records (AAAA)
    -z --zonetransfer                         Perform zone transfer and exit
    -r --recursive                            Recursively scan subdomains
       --recurse-wildcards                    Recursively scan wildcards (slow)

    -m --maxdepth                             Maximum levels to scan recursively
    -a --alterations                          Scan for alterations of subdomains (slow)
    -R --resolver <resolver>                  Use the specified resolver instead of the system default
    -L --resolver-list <file>                 Read list of resolvers from a file
    -T --tld                                  Scan for the domain in all TLDs
    -o --output <filename>                    Output to a text file
    -i --output-ips <filename>                Output discovered IP addresses to a text file
    -n --nocheck                              Don't check nameservers before scanning. Useful in airgapped networks
    -q --quick                                Only perform the zone transfer and subdomain scans. Suppresses most file output with -o
    -N --no-ip                                Don't print IP addresses in the output
    -v --verbose                              Verbose output
    -h --help                                 Display help text

Пользовательские точки вставки можно задать, добавив "%%" в доменное имя, например:

```
$ SubScanPy.py -d dev-%%.example.org
```

Wordlists
---------

Несколько списков слов поставляются вместе с dns can.

Первые четыре (**subdomains-100.txt**, **subdomains-500.txt**, **subdomains-1000.txt ** и **subdomains-10000.txt**) были созданы путем анализа наиболее часто встречающихся подобластей примерно в 86 000 файлах зон, которые были переданы в рамках отдельного исследовательского проекта. Эти списки слов отсортированы по популярности поддоменов (точнее, по проценту зон, которые содержали их в наборе данных).

Списки **subdomain-uk-500.txt** и **subdomain-uk-1000.txt*** создаются с использованием той же методологии, но на основе набора из примерно 180 000 переводов в зоны с доменов ".uk".

Окончательный (и используемый по умолчанию) список слов (**subdomains.txt**) основан на 500 лучших поддоменах по популярности и 500 лучших поддоменах Великобритании, но в него был внесен ряд дополнений вручную на основе доменов, выявленных в ходе тестирования.

Этот список отсортирован в алфавитном порядке и в настоящее время содержит приблизительно **770** записи.


Сканирование TLD
------------
Параметр -T (--tld) можно использовать для поиска всех TLD, в которых существует конкретное доменное имя. По умолчанию будет использоваться **tlds.txt** список, содержащий все TLD, перечисленные IANA (включая новые TLD). Вы также можете указать пользовательский список слов с помощью -w. Прилагаемый файл **suffixes.txt** представляет собой сокращенную версию общедоступного списка суффиксов, поэтому он будет включать большинство доменов второго уровня (таких как co.uk).

Обратите внимание, что при использовании этой опции вам следует указывать только базу доменного имени ("github" и "github.com").

Изменения
-----------
Переключатель "-a"/"--alternations" добавляет различные префиксы и суффиксы (такие как "dev", "test", "01" и т.д.) к доменам, как с дефисами, так и без них. Это приводит к большому количеству дополнительных перестановок (примерно 60 перестановок на домен), поэтому выполняется намного медленнее, особенно при использовании больших списков слов.


Установка
-----

Для работы с dns can требуется Python 3 и библиотеки netaddr (версии 0.7.19 или выше) и dnspython (версии 2.0.0 или выше).

Для установки зависимостей выполните следующую команду:

    $ pip install -r requirements.txt