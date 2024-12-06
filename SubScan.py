#!/usr/bin/env python3

from __future__ import print_function
import packaging.version

import os
import platform
import re
import sys
import threading
import time
import itertools
import string
import logging

logging.basicConfig(level=logging.INFO)

try:    # Уродливый взлом, потому что Python3 решил переименовать Queue в queue очередь
    import Queue
except ImportError:
    import queue as Queue

try:    # Python2 и Python3 имеют разные библиотеки IP-адресов
        from ipaddress import ip_address as ipaddr
except ImportError:
    try:
        from netaddr import IPAddress as ipaddr
    except ImportError:
        if sys.version_info[0] == 2:
            print("ОШИБКА: для SubScan требуются модули netaddr (python-netaddr) или ipaddress (python-ipaddress).")
        else:
            print("ОШИБКА: для SubScan требуются модули netaddr (python3-netaddr) или ip-адрес (стандартная библиотека).")
        sys.exit(1)

try:
    import argparse
except:
    print("ОШИБКА: Отсутствует модуль argparse (python-argparse)")
    sys.exit(1)

try:
    import dns.query
    import dns.resolver
    import dns.zone
    import dns.dnssec
    import dns.message
    import dns.rcode
    import dns.name
    
except:
    print("ОШИБКА: Отсутствует модуль dnspython (python-dnspython)")
    sys.exit(1)

def setup_resolver(resolver_list=None, resolvers=None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    if resolver_list:
        with open(resolver_list, 'r') as f:
            resolver.nameservers = f.read().splitlines()
    elif resolvers:
        resolver.nameservers = resolvers.split(",")
    return resolver

if (packaging.version.parse(dns.__version__) < packaging.version.Version("2.0.0")):
    print("для работы с SubScanPy требуется dnspython версии 2.0.0 или выше.\ Вы можете установить его с помощью `pip install -r requirements.txt`")
    sys.exit(1)

# Использование: SubScan.py -d <доменное имя>

class scanner(threading.Thread):
    def __init__(self, queue, stop_event):
        global wildcard
        threading.Thread.__init__(self)
        self.queue = queue
        self.stop_event = stop_event

    def get_name(self, domain):
        global wildcard, addresses
        try:
            if sys.stdout.isatty():     # Не отправляйте спам-рассылку при перенаправлении
                print(domain + '\033[K\r', end='')

            res = lookup(domain, recordtype)
            if args.tld and res:
                nameservers = sorted(list(res))
                ns0 = str(nameservers[0])[:-1]  # Первый сервер имен
                print('\033[K\r', end='')
                print(domain + " - " + col.brown + ns0 + col.end)
                if outfile:
                    print(ns0 + " - " + domain, file=outfile)
            if args.tld:
                if res:
                    print('\033[K\r', end='')
                    print(domain + " - " + res)
                return
            for rdata in res:
                address = rdata.address
                if wildcard:
                    for wildcard_ip in wildcard:
                        if address == wildcard_ip:
                            return
                print('\033[K\r', end='')
                if args.no_ip:
                    print(col.brown + domain + col.end)
                    break
                elif args.domain_first:
                    print(domain + " - " + col.brown + address + col.end)
                else:
                    print(address + " - " + col.brown + domain + col.end)
                if outfile:
                    if args.domain_first:
                        print(domain + " - " + address, file=outfile)
                    else:
                        print(address + " - " + domain, file=outfile)
                try:
                    addresses.add(ipaddr(unicode(address)))
                except NameError:
                    addresses.add(ipaddr(str(address)))

            if ( domain != target and \
                 args.recurse and \
                 domain.count('.') - target.count('.') <= args.maxdepth
                 ):
                # Проверяем, является ли поддомен подстановочным знаком, чтобы можно было отфильтровать ложные срабатывания при рекурсивном сканировании
                wildcard = get_wildcard(domain)
                for wildcard_ip in wildcard:
                    try:
                        addresses.add(ipaddr(unicode(wildcard_ip)))
                    except NameError:
                        addresses.add(ipaddr(str(wildcard_ip)))
                if args.recurse_wildcards or not wildcard:
                    add_target(domain)  # Рекурсивное сканирование поддоменов
        except:
            pass

    def run(self):
        while not self.stop_event.is_set():
            try:
                domain = self.queue.get(timeout=1)
            except:
                return
            self.get_name(domain)
            self.queue.task_done()


class output:
    def status(self, message):
        print(col.blue + "[*] " + col.end + message)
        if outfile and not args.quick:
            print("[*] " + message, file=outfile)

    def good(self, message):
        print(col.green + "[+] " + col.end + message)
        if outfile and not args.quick:
            print("[+] " + message, file=outfile)

    def verbose(self, message):
        if args.verbose:
            print(col.brown + "[v] " + col.end + message)
            if outfile and not args.quick:
                print("[v] " + message, file=outfile)

    def warn(self, message):
        print(col.red + "[-] " + col.end + message)
        if outfile and not args.quick:
            print("[-] " + message, file=outfile)

    def fatal(self, message):
        print("\n" + col.red + "ОШИБКА: " + message + col.end)
        if outfile and not args.quick:
            print("ОШИБКА " + message, file=outfile)


class col:
    if sys.stdout.isatty() and platform.system() != "Windows":
        green = '\033[32m'
        blue = '\033[94m'
        red = '\033[31m'
        brown = '\033[33m'
        end = '\033[0m'
    else:   # Цвета портят перенаправленный вывод, отключаем их
        green = ""
        blue = ""
        red = ""
        brown = ""
        end = ""


def lookup(domain, recordtype):
    try:
        res = resolver.resolve(domain, recordtype)
        return res
    except:
        return


def get_wildcard(target, recordtype='A'):
    """
    Определяет наличие подстановочного DNS-записи для указанного домена.

    :param target: Домен, для которого необходимо проверить наличие подстановочной записи.
    :param recordtype: Тип DNS-записи для поиска (по умолчанию 'A').
    :return: Список IP-адресов, связанных с подстановочной записью.
    """
    wildcards = []
    epochtime = str(int(time.time()))
    subdomain = "a" + epochtime + "." + target

    try:
        answers = dns.resolver.resolve(subdomain, recordtype)
        for answer in answers:
            address = answer.to_text()
            wildcards.append(address)
            print(f"Найден домен с подстановочным знаком - *.{target} ({address})")
    except dns.resolver.NoAnswer:
        print(f"Не найден домен с подстановочным знаком")
    except dns.resolver.NXDOMAIN:
        print(f"Домен не существует")
    except Exception as e:
        print(f"Ошибка при выполнении DNS-запроса: {e}")

    return wildcards

def get_nameservers(target):
    try:
        ns = resolver.resolve(target, 'NS')
        return ns
    except:
        return

def get_v6(target):
    out.verbose("Получение записей IPv6 (AAAA)")
    try:
        res = lookup(target, "AAAA")
        if res:
            out.good("Найдены записи IPv6 (AAAA). Попробуйте запустить SubScanPy с помощью "+ col.green + "-6 " + col.end + " опции.")
        for v6 in res:
            print(str(v6) + "\n")
            if outfile:
                print(v6, file=outfile)
    except:
        return

def get_txt(target):
    out.verbose("Получение текстовых записей")
    try:
        res = lookup(target, "TXT")
        if res:
            out.good("Записи TXT найдены")
        for txt in res:
            print(txt)
            if outfile:
                print(txt, file=outfile)
        print("")
    except:
        return

def get_dmarc(target):
    out.verbose("Получение записей DMARC")
    try:
        res = lookup("_dmarc." + target, "TXT")
        if res:
            out.good("Найдены записи DMARC")
        for dmarc in res:
            print(dmarc)
            if outfile:
                print(dmarc, file=outfile)
        print("")
    except:
        return

def get_dnssec(target, nameserver):
    out.verbose("Проверка DNSSEC")
    
    try:
        request = dns.message.make_query(target, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(request, nameserver, timeout=1)
    except Exception as e:
        out.warn(f"Ошибка при выполнении DNS-запроса: {e}\n")
        return

    if response.rcode() != dns.rcode.NOERROR:
        out.warn(f"DNSKEY поиск вернул код ошибки: {dns.rcode.to_text(response.rcode())}\n")
        return

    answer = response.answer
    if not answer:
        out.warn("DNSSEC не поддерживается\n")
        return

    if len(answer) != 2:
        out.warn("Недопустимая длина записи DNSKEY\n")
        return

    name = dns.name.from_text(target)
    try:
        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dns.dnssec.ValidationFailure:
        out.warn("Не удалось выполнить проверку ключа DNSSEC\n")
    except Exception as e:
        out.warn(f"Ошибка при проверке DNSSEC: {e}\n")
    else:
        out.good("DNSSEC активен и проверен")
        try:
            dnssec_values = str(answer[0][0]).split(' ')
            algorithm_int = int(dnssec_values[2])
            algorithm_str = dns.dnssec.algorithm_to_text(algorithm_int)
            print(f"Алгоритм = {algorithm_str} ({algorithm_int})\n")
        except Exception as e:
            out.warn(f"Ошибка при извлечении информации об алгоритме: {e}\n")

def get_mx(target):
    out.verbose("Получаем записи MX")
    try:
        res = lookup(target, "MX")
    except:
        return
    # Возвращяем, если мы не получим обратно ни одной записи MX
    if not res:
        return
    out.good("MX найденные записи добавлены в целевой список")
    for mx in res:
        print(mx.to_text())
        if outfile:
            print(mx.to_text(), file=outfile)
        mxsub = re.search("([a-z0-9\.\-]+)\."+target, mx.to_text(), re.IGNORECASE)
        try:
            if mxsub.group(1) and mxsub.group(1) not in wordlist:
                queue.put(mxsub.group(1) + "." + target)
        except AttributeError:
            pass
    print("")

def zone_transfer(domain, ns, nsip):
    out.verbose("Попытка переноса зоны против " + str(ns))
    try:
        print(str(domain))
        zone = dns.zone.from_xfr(dns.query.xfr(str(nsip), domain, relativize=False, timeout=3),
                                 relativize=False)
        out.good("Успешная передача зоны с использованием сервера имен " + col.brown + str(ns) + col.end)
        names = list(zone.nodes.keys())
        names.sort()
        for n in names:
            print(zone[n].to_text(n))    # Print raw zone
            if outfile:
                print(zone[n].to_text(n), file=outfile)
        sys.exit(0)
    except Exception:
        pass

def generate_subdomains(length):
    if '-' in length:
        min_len, max_len = map(int, length.split('-'))
    else:
        min_len = 1
        max_len = int(length)

    characters = string.ascii_lowercase + string.digits

    for sub_len in range(min_len, max_len + 1):
        for subdomain_tuple in itertools.product(characters, repeat=sub_len):
            yield ''.join(subdomain_tuple)

def add_target(domain):
    if args.bruteforce:
        subdomains = generate_subdomains(args.bruteforce)
        for subdomain in subdomains:
            queue.put(subdomain + "." + domain)
    else:
        for word in wordlist:
            patterns = [word]
            if args.alt:
                probes = ["dev", "prod", "stg", "qa", "uat", "api", "alpha", "beta",
                          "cms", "test", "internal", "staging", "origin", "stage"]
                for probe in probes:
                    if probe not in word: # Сократите изменения, которых, скорее всего, не существует (например, dev-dev.domain.com)
                        patterns.append(probe + word)
                        patterns.append(word + probe)
                        patterns.append(probe + "-" + word)
                        patterns.append(word + "-" + probe)
                if not word[-1].isdigit(): # Если у поддомена уже был номер в качестве суффикса
                    for n in range(1, 6):
                        patterns.append(word + str(n))
                        patterns.append(word + "0" + str(n))
            for pattern in patterns:
                if '%%' in domain:
                    queue.put(domain.replace(r'%%', pattern))
                else:
                    queue.put(pattern + "." + domain)       

def add_tlds(domain):
    for tld in wordlist:
        queue.put(domain + "." + tld)
        
def get_args():
    global args
    
    parser = argparse.ArgumentParser(
        'SubScan.py',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
        epilog="Укажите пользовательскую точку вставки с %% в имени домена, например: SubScan.py -d dev-%%.example.org"
    )
    target = parser.add_mutually_exclusive_group(required=True)  # Позволяет пользователю указать список целевых доменов
    target.add_argument('-d', '--domain', help='Целевые домены (разделенные запятыми)', dest='domain', required=False)
    target.add_argument('-l', '--list', help='Файл, содержащий список целевых доменов', dest='domain_list', required=False)
    parser.add_argument('-w', '--wordlist', help='Словарь', dest='wordlist', required=False)
    parser.add_argument('-t', '--threads', help='Количество потоков', dest='threads', required=False, type=int, default=8)
    parser.add_argument('-6', '--ipv6', action="store_true", help='Сканировать записи AAAA', dest='ipv6')
    parser.add_argument('-z', '--zonetransfer', action="store_true", help='Только выполнять передачу зоны', dest='zonetransfer')
    parser.add_argument('-r', '--recursive', action="store_true", help="Рекурсивно сканировать поддомены", dest='recurse')
    parser.add_argument('--recurse-wildcards', action="store_true", help="Рекурсивно сканировать подстановочные знаки (медленно)", dest='recurse_wildcards')
    parser.add_argument('-m', '--maxdepth', help='Максимальная глубина рекурсии (для перебора)', dest='maxdepth', required=False, type=int, default=5)
    parser.add_argument('-a', '--alterations', action="store_true", help='Сканировать изменения поддоменов (медленно)', dest='alt')
    parser.add_argument('-R', '--resolver', help="Использовать указанные резолверы (разделенные запятыми)", dest='resolvers', required=False)
    parser.add_argument('-L', '--resolver-list', help="Файл, содержащий список резолверов", dest='resolver_list', required=False)
    parser.add_argument('-T', '--tld', action="store_true", help="Сканировать TLD", dest='tld')
    parser.add_argument('-o', '--output', help="Записать вывод в файл", dest='output_filename', required=False)
    parser.add_argument('-i', '--output-ips', help="Записать обнаруженные IP-адреса в файл", dest='output_ips', required=False)
    parser.add_argument('-D', '--domain-first', action="store_true", help='Выводить сначала домен, а не IP-адрес', dest='domain_first')
    parser.add_argument('-N', '--no-ip', action="store_true", help='Не выводить IP-адреса в выводе', dest='no_ip')
    parser.add_argument('-v', '--verbose', action="store_true", help='Подробный режим', dest='verbose')
    parser.add_argument('-n', '--nocheck', action="store_true", help='Не проверять серверы имен перед сканированием', dest='nocheck')
    parser.add_argument('-q', '--quick', action="store_true", help='Только выполнять передачу зоны и сканирование поддоменов с минимальным выводом в файл', dest='quick')
    parser.add_argument('-b', '--bruteforce', help='Длина генерируемого поддомена в формате 6 или 3-8', dest='bruteforce', required=False)
    
    args = parser.parse_args()

def setup():
    global targets, wordlist, queue, resolver, recordtype, outfile, outfile_ips
    if args.domain:
        targets = args.domain.split(",")
    if args.tld and not args.wordlist:
        args.wordlist = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tlds.txt")
    else:
        if not args.wordlist:   # Пробую использовать список слов по умолчанию, если он не указан
            args.wordlist = os.path.join(os.path.dirname(os.path.realpath(__file__)), "subdomains.txt")

    # Открываю дескриптор файла для вывода
    try:
        outfile = open(args.output_filename, "w")
    except TypeError:
        outfile = None
    except IOError:
        out.fatal("Не удалось открыть выходной файл: " + args.output_filename)
        sys.exit(1)
    if args.output_ips:
        outfile_ips = open(args.output_ips, "w")
    else:
        outfile_ips = None

    try:
        wordlist = open(args.wordlist).read().splitlines()
    except:
        out.fatal("Не могу открыть словарь " + args.wordlist)
        sys.exit(1)
    # Количество тредов должно быть между 1 и 32
    if args.threads < 1:
        args.threads = 1
    elif args.threads > 32:
        args.threads = 32
    queue = Queue.Queue()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    if args.resolver_list:
        try:
            resolver.nameservers = open(args.resolver_list, 'r').read().splitlines()
        except FileNotFoundError:
            out.fatal("Не удалось открыть файл, содержащий ресолверы: " + args.resolver_list)
            sys.exit(1)
    elif args.resolvers:
        resolver.nameservers = args.resolvers.split(",")

    # Record type
    if args.ipv6:
        recordtype = 'AAAA'
    elif args.tld:
        recordtype = 'NS'
    else:
        recordtype = 'A'


if __name__ == "__main__":
    global wildcard, addresses, outfile_ips
    addresses = set([])
    out = output()
    get_args()
    setup()
    resolver = setup_resolver(args.resolver_list, args.resolvers)
    stop_event = threading.Event()  # Создаем событие для остановки потоков
    if args.nocheck == False:
        try:
            resolver.resolve('.', 'NS')
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            out.warn("Не удалось разрешить '.' - возможно, сервер работает неправильно. Все равно продолжаем....")
            pass
        except:
            out.fatal("Не работает ресолвер DNS. Это может произойти, если сервер разрешает только внутренние зоны")
            out.fatal("Установите пользовательский преобразователь с помощью -R <преобразователь>")
            out.fatal("Проигнорируйте это предупреждение с помощью -n -nocheck\n")
            sys.exit(1)

    if args.domain_list:
        out.verbose("Предоставленный список доменов будет разбирать {} для доменов.".format(args.domain_list))
        if not os.path.isfile(args.domain_list):
            out.fatal("Список доменов {} не существует!".format(args.domain_list))
            sys.exit(1)
        with open(args.domain_list, 'r') as domain_list:
            try:
                targets = list(filter(bool, domain_list.read().split('\n')))
            except Exception as e:
                out.fatal("Не могу прочитать {}, {}".format(args.domain_list, e))
                sys.exit(1)
    for subtarget in targets:
        global target
        target = subtarget
        out.status("Область обработки {}".format(target))
        if args.resolver_list:
            out.status("Использование DNS ресолверов из: {}".format(args.resolver_list))
        elif args.resolvers:
            out.status("Использование указанных преобразователей: {}".format(args.resolvers))
        else:
            out.status("Использование системных DNS ресолверов: {}".format(",".join(resolver.nameservers)))
        if args.tld and not '%%' in target:
            if "." in target:
                out.warn("Внимание: сканирование TLD лучше всего работает только с корневым доменом")
            out.good("Сканирование TLD")
            add_tlds(target)
        else:
            queue.put(target)   # Добавьте реальный домен, а также поддомены

            # Все эти проверки не будут выполнены, если у нас есть пользовательская точка ввода, поэтому пропустите их
            if not '%%' in target:
                nameservers = get_nameservers(target)
                out.good("Получаем nameservers")
                targetns = []       # NS сервера для цели
                nsip = None
                try:    # Поддомены часто не содержат записей NS..
                    for ns in nameservers:
                        ns = str(ns)[:-1]   # Удалена конечная точка
                        res = lookup(ns, "A")
                        for rdata in res:
                            targetns.append(rdata.address)
                            nsip = rdata.address
                            print(nsip + " - " + col.brown + ns + col.end)
                            if not args.quick:
                                if outfile:
                                    print(nsip + " - " + ns, file=outfile)
                        zone_transfer(target, ns, nsip)
                except SystemExit:
                    sys.exit(0)
                except:
                    out.warn("Не удалось получить доступ к серверам имен")
                out.warn("Не удалось перенести зону\n")
                if args.zonetransfer:
                    sys.exit(0)

                if not args.quick:
                    get_v6(target)
                    get_txt(target)
                    get_dmarc(target)

                    # Для этих проверок требуется соответствующий сервер имен, системная заглушка не работает
                    if nsip:
                        get_dnssec(target, nsip)
                    else:
                        get_dnssec(target, resolver.nameservers[0])
                    get_mx(target)
            wildcard = get_wildcard(target)
            for wildcard_ip in wildcard:
                try:
                    addresses.add(ipaddr(unicode(wildcard_ip)))
                except NameError:
                    addresses.add(ipaddr(str(wildcard_ip)))
            out.status("Сканирую  " + target + " для " + recordtype + " записей")
            add_target(target)

        for i in range(args.threads):
            t = scanner(queue, stop_event)
            t.daemon = True
            t.start()
        try:
            for i in range(args.threads):
                t.join(1024)       # Таймаут
        except KeyboardInterrupt:
            out.fatal("Поймал прерывание с клавиатуры, завершаю работу...")
            stop_event.set()  # Устанавливаем флаг остановки
            if outfile:
                outfile.close()
            sys.exit(1)
        print("                                        ")
        if outfile_ips:
            for address in sorted(addresses):
                print(address, file=outfile_ips)
    if outfile:
        outfile.close()
    if outfile_ips:
        outfile_ips.close()