# Copyright (c) 2013-2024 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""SSH listeners"""

import asyncio
import errno
import ipaddress
import random
import socket
from types import TracebackType
from typing import TYPE_CHECKING, AnyStr, Callable, Dict, Generic, List
from typing import Optional, Sequence, Set, Tuple, Type, Union
from typing_extensions import Self

from .forward import SSHForwarderCoro
from .forward import SSHLocalPortForwarder, SSHLocalPathForwarder
from .misc import HostPort, IPNetwork, MaybeAwait, ip_address
from .session import SSHTCPSession, SSHUNIXSession
from .socks import SSHSOCKSForwarder


if TYPE_CHECKING:
    # pylint: disable=cyclic-import
    from .channel import SSHTCPChannel, SSHUNIXChannel
    from .connection import SSHConnection, SSHClientConnection
    from .connection import SSHServerConnectionOptions


_LocalListenerFactory = Callable[[], asyncio.BaseProtocol]

ListenKey = Union[HostPort, str]

TCPListenerFactory = Callable[[str, int], MaybeAwait[SSHTCPSession[AnyStr]]]
UNIXListenerFactory = Callable[[], MaybeAwait[SSHUNIXSession[AnyStr]]]


class _StartupsReservation:
    """Reservation of slots held by one unauthenticated connection"""

    __slots__ = ('_limiter', '_source', '_released')

    def __init__(self, limiter: '_StartupsLimiter',
                 source: Optional[IPNetwork]) -> None:
        self._limiter = limiter
        self._source = source
        self._released = False

    def release(self) -> None:
        """Release the reserved slots

           This is idempotent and safe to call both when a connection
           completes authentication and when it is closed while still
           unauthenticated.

        """

        if not self._released:
            self._released = True
            self._limiter._release(self._source)  # pylint: disable=protected-access


class _StartupsLimiter:
    """Limit unauthenticated connections accepted by a listener

       This implements OpenSSH-compatible MaxStartups random early
       dropping and per-source netblock startup limits. Limits are
       read from the listener's options at accept time, so option
       changes (including via SSHAcceptor.update) apply to newly
       accepted connections without losing existing counters.

    """

    def __init__(self, options: 'SSHServerConnectionOptions') -> None:
        self._options = options
        self._total = 0
        self._sources: Dict[IPNetwork, int] = {}

    @property
    def total(self) -> int:
        """Return the current number of unauthenticated connections"""

        return self._total

    def _get_source(self, peer_addr: str) -> Optional[IPNetwork]:
        """Return the source netblock a peer address belongs to"""

        per_source_max = self._options.per_source_max_startups

        if not peer_addr or per_source_max is None:
            return None

        try:
            addr = ip_address(peer_addr)
        except ValueError:
            return None

        block_sizes = self._options.per_source_net_block_size or (32, 128)
        prefixlen = block_sizes[0] if addr.version == 4 else block_sizes[1]

        return ipaddress.ip_network(f'{str(addr)}/{prefixlen}', strict=False)

    def admit(self, peer_addr: str) -> Optional[_StartupsReservation]:
        """Try to reserve slots for a new unauthenticated connection

           Returns a reservation to release later if the connection is
           allowed, or None if it should be dropped before beginning
           the SSH handshake.

        """

        source = self._get_source(peer_addr)
        per_source_max = self._options.per_source_max_startups

        if source is not None:
            assert per_source_max is not None

            source_count = self._sources.get(source, 0)

            if source_count >= per_source_max:
                return None

        max_startups = self._options.max_startups

        if max_startups is not None:
            start, rate, full = max_startups
            count = self._total

            if count >= full:
                return None

            # Drop probability grows linearly from 0 to rate percent as
            # the number of unauthenticated connections goes from start
            # to full.
            if (rate is not None and count >= start and
                    random.random() * 100 <
                    rate * (count - start) / (full - start)):
                return None

        self._total += 1

        if source is not None:
            self._sources[source] = source_count + 1

        return _StartupsReservation(self, source)

    def _release(self, source: Optional[IPNetwork]) -> None:
        """Release slots held by an authenticated or closed connection"""

        self._total -= 1

        if source is not None:
            count = self._sources[source] - 1

            if count:
                self._sources[source] = count
            else:
                del self._sources[source]


class SSHListener:
    """SSH listener for inbound connections"""

    def __init__(self) -> None:
        self._tunnel: Optional['SSHConnection'] = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, _exc_type: Optional[Type[BaseException]],
                        _exc_value: Optional[BaseException],
                        _traceback: Optional[TracebackType]) -> bool:
        self.close()
        await self.wait_closed()
        return False

    def get_port(self) -> int:
        """Return the port number being listened on

           This method returns the port number that the remote listener
           was bound to. When the requested remote listening port is `0`
           to indicate a dynamic port, this method can be called to
           determine what listening port was selected. This function
           only applies to TCP listeners.

           :returns: The port number being listened on

        """

        # pylint: disable=no-self-use

        return 0

    def set_tunnel(self, tunnel: 'SSHConnection') -> None:
        """Set tunnel associated with listener"""

        self._tunnel = tunnel

    def close(self) -> None:
        """Stop listening for new connections

           This method can be called to stop listening for connections.
           Existing connections will remain open.

        """

        if self._tunnel:
            self._tunnel.close()

    async def wait_closed(self) -> None:
        """Wait for the listener to close

           This method is a coroutine which waits for the associated
           listeners to be closed.

        """

        if self._tunnel:
            await self._tunnel.wait_closed()
            self._tunnel = None


class SSHClientListener(SSHListener):
    """Client listener used to accept inbound forwarded connections"""

    def __init__(self, conn: 'SSHClientConnection', encoding: Optional[str],
                 errors: str, window: int, max_pktsize: int):
        super().__init__()

        self._conn: Optional['SSHClientConnection'] = conn
        self._encoding = encoding
        self._errors = errors
        self._window = window
        self._max_pktsize = max_pktsize
        self._close_event = asyncio.Event()

    async def _close(self) -> None:
        """Close this listener"""

        self._close_event.set()
        self._conn = None

    def close(self) -> None:
        """Close this listener asynchronously"""

        super().close()

        if self._conn:
            self._conn.create_task(self._close())

    async def wait_closed(self) -> None:
        """Wait for this listener to finish closing"""

        await super().wait_closed()

        await self._close_event.wait()


class SSHTCPClientListener(SSHClientListener, Generic[AnyStr]):
    """Client listener used to accept inbound forwarded TCP connections"""

    def __init__(self, conn: 'SSHClientConnection',
                 session_factory: TCPListenerFactory[AnyStr],
                 listen_host: str, listen_port: int,
                 encoding: Optional[str], errors: str,
                 window: int, max_pktsize: int):
        super().__init__(conn, encoding, errors, window, max_pktsize)

        self._session_factory: TCPListenerFactory[AnyStr] = session_factory
        self._listen_host = listen_host
        self._listen_port = listen_port

    async def _close(self) -> None:
        """Close this listener"""

        if self._conn: # pragma: no branch
            await self._conn.close_client_tcp_listener(self._listen_host,
                                                       self._listen_port)

        await super()._close()

    def process_connection(self, orig_host: str, orig_port: int) -> \
            Tuple['SSHTCPChannel[AnyStr]',
                  MaybeAwait[SSHTCPSession[AnyStr]]]:
        """Process a forwarded TCP connection"""

        assert self._conn is not None

        chan = self._conn.create_tcp_channel(self._encoding, self._errors,
                                             self._window, self._max_pktsize)

        chan.set_inbound_peer_names(self._listen_host, self._listen_port,
                                    orig_host, orig_port)

        return chan, self._session_factory(orig_host, orig_port)

    def get_addresses(self) -> List[Tuple]:
        """Return the socket addresses being listened on"""

        return [(self._listen_host, self._listen_port)]

    def get_port(self) -> int:
        """Return the port number being listened on"""

        return self._listen_port


class SSHUNIXClientListener(SSHClientListener, Generic[AnyStr]):
    """Client listener used to accept inbound forwarded UNIX connections"""

    def __init__(self, conn: 'SSHClientConnection',
                 session_factory: UNIXListenerFactory[AnyStr],
                 listen_path: str, encoding: Optional[str],
                 errors: str, window: int, max_pktsize: int):
        super().__init__(conn, encoding, errors, window, max_pktsize)

        self._session_factory: UNIXListenerFactory[AnyStr] = session_factory
        self._listen_path = listen_path

    async def _close(self) -> None:
        """Close this listener"""

        if self._conn: # pragma: no branch
            await self._conn.close_client_unix_listener(self._listen_path)

        await super()._close()

    def process_connection(self) -> \
            Tuple['SSHUNIXChannel[AnyStr]',
                  MaybeAwait[SSHUNIXSession[AnyStr]]]:
        """Process a forwarded UNIX connection"""

        assert self._conn is not None

        chan = self._conn.create_unix_channel(self._encoding, self._errors,
                                              self._window, self._max_pktsize)

        chan.set_inbound_peer_names(self._listen_path)

        return chan, self._session_factory()


class SSHForwardListener(SSHListener):
    """A listener used when forwarding traffic from local ports"""

    def __init__(self, conn: 'SSHConnection',
                 servers: Sequence[asyncio.AbstractServer],
                 listen_key: ListenKey, listen_port: int = 0):
        super().__init__()

        self._conn: Optional['SSHConnection'] = conn
        self._servers = servers
        self._listen_key = listen_key
        self._listen_port = listen_port

    def get_port(self) -> int:
        """Return the port number being listened on"""

        return self._listen_port

    def close(self) -> None:
        """Close this listener"""

        if self._conn: # pragma: no branch
            self._conn.close_forward_listener(self._listen_key)

            for server in self._servers:
                server.close()

            self._conn = None

    async def wait_closed(self) -> None:
        """Wait for this listener to finish closing"""

        await super().wait_closed()

        for server in self._servers:
            await server.wait_closed()

        self._servers = []


async def create_tcp_local_listener(
        conn: 'SSHConnection', loop: asyncio.AbstractEventLoop,
        protocol_factory: _LocalListenerFactory, listen_host: str,
        listen_port: int) -> 'SSHForwardListener':
    """Create a listener to forward traffic from a local TCP port over SSH"""

    addrinfo = await loop.getaddrinfo(listen_host or None, listen_port,
                                      family=socket.AF_UNSPEC,
                                      type=socket.SOCK_STREAM,
                                      flags=socket.AI_PASSIVE)

    if not addrinfo: # pragma: no cover
        raise OSError('getaddrinfo() returned empty list')

    seen_addrinfo: Set[Tuple] = set()
    servers: List[asyncio.AbstractServer] = []

    for addrinfo_entry in addrinfo:
        # Work around an issue where getaddrinfo() on some systems may
        # return duplicate results, causing bind to fail.
        if addrinfo_entry in seen_addrinfo: # pragma: no cover
            continue

        seen_addrinfo.add(addrinfo_entry)

        family, socktype, proto, _, sa = addrinfo_entry

        try:
            sock = socket.socket(family, socktype, proto)
        except OSError: # pragma: no cover
            continue

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
            except AttributeError: # pragma: no cover
                pass

        if sa[1] == 0:
            sa = sa[:1] + (listen_port,) + sa[2:] # type: ignore

        try:
            sock.bind(sa)
        except (OSError, OverflowError) as exc:
            sock.close()

            for server in servers:
                server.close()

            if isinstance(exc, OverflowError): # pragma: no cover
                exc.errno = errno.EOVERFLOW # type: ignore
                exc.strerror = str(exc) # type: ignore

            # pylint: disable=no-member
            raise OSError(exc.errno, f'error while attempting ' # type: ignore
                          f'to bind on address {sa!r}: '
                          f'{exc.strerror}') from None # type: ignore

        if listen_port == 0:
            listen_port = sock.getsockname()[1]
            conn.logger.debug1('Assigning dynamic port %d', listen_port)

        server = await loop.create_server(protocol_factory, sock=sock)
        servers.append(server)

    listen_key = listen_host or '', listen_port
    return SSHForwardListener(conn, servers, listen_key, listen_port)


async def create_tcp_forward_listener(conn: 'SSHConnection',
                                      loop: asyncio.AbstractEventLoop,
                                      coro: SSHForwarderCoro, listen_host: str,
                                      listen_port: int) -> \
        'SSHForwardListener':
    """Create a listener to forward traffic from a local TCP port over SSH"""

    def protocol_factory() -> asyncio.BaseProtocol:
        """Start a port forwarder for each new local connection"""

        return SSHLocalPortForwarder(conn, coro)

    return await create_tcp_local_listener(conn, loop, protocol_factory,
                                           listen_host, listen_port)


async def create_unix_forward_listener(conn: 'SSHConnection',
                                       loop: asyncio.AbstractEventLoop,
                                       coro: SSHForwarderCoro,
                                       listen_path: str) -> \
        'SSHForwardListener':
    """Create a listener to forward a local UNIX domain socket over SSH"""

    def protocol_factory() -> asyncio.BaseProtocol:
        """Start a path forwarder for each new local connection"""

        return SSHLocalPathForwarder(conn, coro)

    server = await loop.create_unix_server(protocol_factory, listen_path)

    return SSHForwardListener(conn, [server], listen_path)


async def create_socks_listener(conn: 'SSHConnection',
                                loop: asyncio.AbstractEventLoop,
                                coro: SSHForwarderCoro, listen_host: str,
                                listen_port: int) -> SSHForwardListener:
    """Create a SOCKS listener to forward traffic over SSH"""

    def protocol_factory() -> asyncio.BaseProtocol:
        """Start a port forwarder for each new SOCKS connection"""

        return SSHSOCKSForwarder(conn, coro)

    return await create_tcp_local_listener(conn, loop, protocol_factory,
                                           listen_host, listen_port)
