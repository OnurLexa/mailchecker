import re
import socket
import smtplib
import dns.resolver
import sys
from contextlib import closing

EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "tempmail.com", "trashmail.com",
    "yopmail.com", "guerrillamail.com"
}

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "yandex.com", "protonmail.com", "mail.com"
}

ROLE_BASE_USERS = {
    "admin", "administrator", "info", "support", "sales", "contact", "webmaster", "postmaster"
}

SMTP_TIMEOUT = 8  # saniye

def valid_format(email):
    return bool(EMAIL_RE.match(email))

def split_email(email):
    user, domain = email.rsplit("@", 1)
    return user.lower(), domain.lower()

def is_disposable(domain):
    return domain in DISPOSABLE_DOMAINS

def is_free_mail(domain):
    return domain in FREE_MAIL_DOMAINS

def is_role_based(user):
    base = user.split('+', 1)[0].split('.', 1)[0]
    return base in ROLE_BASE_USERS

def has_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0, [r.exchange.to_text(omit_final_dot=True) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False, []

def smtp_check(email, mx_hosts):
    from_addr = "verify@example.com"  
    for host in mx_hosts:
        try:
            with closing(smtplib.SMTP(host, 25, timeout=SMTP_TIMEOUT)) as smtp:
                smtp.set_debuglevel(0)
                smtp.helo()  
                smtp.mail(from_addr)
                code, message = smtp.rcpt(email)
                if code in (250, 251):
                    return True, host, code, message.decode() if isinstance(message, bytes) else message
                else:
                    return False, host, code, message.decode() if isinstance(message, bytes) else message
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPRecipientsRefused,
                socket.timeout, ConnectionRefusedError, OSError) as e:
            continue
    return False, None, None, None

def summarize(result):
    print("\n--- Kontrol Özeti ---")
    print(f"Email: {result['email']}")
    print(f"Success (format geçerli?): {result['valid-format']}")
    print(f"Deliverable (SMTP cevap): {result['deliverable']}")
    print(f"Disposable domain: {result['disposable']}")
    print(f"Role-based user: {result['role-base']}")
    print(f"Free-mail provider: {result['free-mail']}")
    print(f"Server (MX record) var mı: {result['server-status']}")
    print(f"Email domain: {result['email-domain']}")
    print(f"Email user: {result['email-user']}")
    if result.get("notes"):
        print("\nNotlar:")
        for n in result["notes"]:
            print("-", n)
    print("---------------------\n")

def main():
    try:
        email = input("Kontrol etmek istediğin mail adresini gir: ").strip()
    except KeyboardInterrupt:
        print("\nİptal edildi.")
        sys.exit(0)

    result = {
        "success": True,
        "email": email,
        "deliverable": False,
        "valid-format": False,
        "disposable": False,
        "role-base": False,
        "free-mail": False,
        "server-status": False,
        "email-domain": None,
        "email-user": None,
        "notes": []
    }

    if not valid_format(email):
        result["valid-format"] = False
        result["success"] = False
        result["notes"].append("E-posta formatı geçersiz.")
        summarize(result)
        return

    result["valid-format"] = True
    user, domain = split_email(email)
    result["email-domain"] = domain
    result["email-user"] = user

    if is_disposable(domain):
        result["disposable"] = True
        result["notes"].append("Domain bilinen disposable sağlayıcı listesinde.")
    else:
        result["disposable"] = False

    if is_free_mail(domain):
        result["free-mail"] = True
    else:
        result["free-mail"] = False

    if is_role_based(user):
        result["role-base"] = True
    else:
        result["role-base"] = False

    mx_ok, mx_hosts = has_mx(domain)
    result["server-status"] = mx_ok
    if not mx_ok:
        result["notes"].append("Domain için MX kaydı bulunamadı veya DNS sorgusu zaman aşımına uğradı.")
        summarize(result)
        return

    deliverable, host, code, message = smtp_check(email, mx_hosts)
    result["deliverable"] = bool(deliverable)
    if host:
        result["notes"].append(f"SMTP testi denendi: MX host={host}, kod={code}, mesaj={message}")
    else:
        result["notes"].append("SMTP testi yapılamadı (tüm MX hostlara bağlantı başarısız veya reddedildi).")

    summarize(result)

if __name__ == "__main__":
    main()
