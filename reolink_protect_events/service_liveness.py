"""Small systemd notifications tied to actual service-loop progress."""
import os
import socket


def notify(message):
    address=os.environ.get('NOTIFY_SOCKET')
    if not address or not hasattr(socket,'AF_UNIX'):
        return False
    if not isinstance(message,str) or '\0' in message:
        raise ValueError('invalid_service_notification')
    expected=os.environ.get('WATCHDOG_PID')
    if expected and expected!=str(os.getpid()):
        return False
    if address.startswith('@'):
        address='\0'+address[1:]
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)as stream:
            stream.settimeout(.2)
            stream.connect(address)
            stream.sendall(message.encode('ascii'))
        return True
    except (OSError,UnicodeError):
        return False
