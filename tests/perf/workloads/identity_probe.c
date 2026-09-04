#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

enum {
    EXIT_PROBE_FAILED = 2,
    EXIT_USAGE_ERROR = 64,
    MAX_TIMEOUT_MS = 10000,
    MIN_TIMEOUT_MS = 50,
    MAX_RESPONSE_BYTES = 4096,
    HTTP_BUFFER_BYTES = 8192 + MAX_RESPONSE_BYTES + 1,
    TCP_REQUEST_BYTES = 32,
    TCP_RESPONSE_BYTES = 44,
    UDP_REQUEST_BYTES = 40,
    UDP_RESPONSE_BYTES = 52
};

static uint64_t monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void put_u32(uint8_t *target, uint32_t value) {
    target[0] = (uint8_t)(value >> 24);
    target[1] = (uint8_t)(value >> 16);
    target[2] = (uint8_t)(value >> 8);
    target[3] = (uint8_t)value;
}

static void put_u64(uint8_t *target, uint64_t value) {
    for (unsigned int index = 0; index < 8; ++index) {
        target[index] = (uint8_t)(value >> (56U - index * 8U));
    }
}

static uint32_t get_u32(const uint8_t *source) {
    return ((uint32_t)source[0] << 24) | ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) | (uint32_t)source[3];
}

static uint64_t get_u64(const uint8_t *source) {
    uint64_t result = 0;
    for (unsigned int index = 0; index < 8; ++index) {
        result = (result << 8) | source[index];
    }
    return result;
}

static bool parse_bounded(const char *text, unsigned long minimum,
                          unsigned long maximum, unsigned long *result) {
    char *end = NULL;
    errno = 0;
    const unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
        parsed > maximum) {
        return false;
    }
    *result = parsed;
    return true;
}

static int set_timeouts(int descriptor, unsigned long timeout_ms) {
    struct timeval timeout;
    timeout.tv_sec = (time_t)(timeout_ms / 1000UL);
    timeout.tv_usec = (suseconds_t)((timeout_ms % 1000UL) * 1000UL);
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        return -1;
    }
    return 0;
}

static int connect_numeric(const char *host, const char *port, int socket_type,
                           unsigned long timeout_ms) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socket_type;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        errno = EINVAL;
        return -1;
    }

    int connected = -1;
    int saved_error = ECONNREFUSED;
    for (const struct addrinfo *candidate = addresses; candidate != NULL;
         candidate = candidate->ai_next) {
        int descriptor = socket(candidate->ai_family, candidate->ai_socktype,
                                candidate->ai_protocol);
        if (descriptor < 0) {
            saved_error = errno;
            continue;
        }
        int flags = fcntl(descriptor, F_GETFL, 0);
        if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
            saved_error = errno;
            close(descriptor);
            continue;
        }
        int status = connect(descriptor, candidate->ai_addr, candidate->ai_addrlen);
        if (status != 0 && errno == EINPROGRESS) {
            struct pollfd poll_descriptor = {.fd = descriptor, .events = POLLOUT};
            status = poll(&poll_descriptor, 1, (int)timeout_ms);
            if (status > 0) {
                socklen_t length = sizeof(saved_error);
                if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &saved_error,
                               &length) != 0) {
                    saved_error = errno;
                }
                status = saved_error == 0 ? 0 : -1;
            } else {
                saved_error = status == 0 ? ETIMEDOUT : errno;
                status = -1;
            }
        } else if (status != 0) {
            saved_error = errno;
        }
        if (status == 0 && fcntl(descriptor, F_SETFL, flags) == 0 &&
            set_timeouts(descriptor, timeout_ms) == 0) {
            connected = descriptor;
            break;
        }
        if (status == 0) {
            saved_error = errno;
        }
        close(descriptor);
    }
    freeaddrinfo(addresses);
    if (connected < 0) {
        errno = saved_error;
    }
    return connected;
}

static int send_all(int descriptor, const uint8_t *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t sent = send(descriptor, data + offset, length - offset, 0);
        if (sent <= 0) {
            return -1;
        }
        offset += (size_t)sent;
    }
    return 0;
}

static int receive_exact(int descriptor, uint8_t *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t received = recv(descriptor, data + offset, length - offset, 0);
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int probe_tcp_framed(int descriptor, uint32_t response_size,
                            uint64_t sent_ns) {
    uint8_t request[TCP_REQUEST_BYTES];
    memset(request, 0, sizeof(request));
    memcpy(request, "OSPF", 4);
    request[4] = 1;
    request[5] = 1;
    put_u32(request + 8, 0);
    put_u32(request + 12, response_size);
    put_u64(request + 16, 1);
    put_u64(request + 24, sent_ns);
    if (send_all(descriptor, request, sizeof(request)) != 0) {
        return -1;
    }
    uint8_t response[TCP_RESPONSE_BYTES];
    if (receive_exact(descriptor, response, sizeof(response)) != 0 ||
        memcmp(response, "OSPR", 4) != 0 || response[4] != 1 ||
        response[5] != 0 || get_u32(response + 8) != response_size ||
        get_u64(response + 12) != 1 || get_u64(response + 20) != sent_ns) {
        errno = EPROTO;
        return -1;
    }
    uint8_t body[MAX_RESPONSE_BYTES];
    return receive_exact(descriptor, body, response_size);
}

static int probe_tcp_http(int descriptor, const char *host,
                          uint32_t response_size, uint64_t sent_ns) {
    char request[1024];
    char authority[INET6_ADDRSTRLEN + 3];
    int authority_length = strchr(host, ':') == NULL
                               ? snprintf(authority, sizeof(authority), "%s", host)
                               : snprintf(authority, sizeof(authority), "[%s]", host);
    if (authority_length <= 0 || (size_t)authority_length >= sizeof(authority)) {
        errno = EINVAL;
        return -1;
    }
    int length = snprintf(
        request, sizeof(request),
        "POST /bytes/%" PRIu32 " HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
        "Content-Type: application/octet-stream\r\nContent-Length: 0\r\n"
        "X-OpenShield-Request-Id: %020d\r\n"
        "X-OpenShield-Sent-Ns: %020" PRIu64 "\r\n\r\n",
        response_size, authority, 1, sent_ns);
    if (length <= 0 || (size_t)length >= sizeof(request) ||
        send_all(descriptor, (const uint8_t *)request, (size_t)length) != 0) {
        errno = EPROTO;
        return -1;
    }

    uint8_t response[HTTP_BUFFER_BYTES];
    size_t used = 0;
    char *delimiter = NULL;
    while (used < sizeof(response) - 1) {
        ssize_t received = recv(descriptor, response + used,
                                sizeof(response) - 1 - used, 0);
        if (received <= 0) {
            return -1;
        }
        used += (size_t)received;
        response[used] = '\0';
        delimiter = strstr((char *)response, "\r\n\r\n");
        if (delimiter != NULL) {
            break;
        }
        if (used > 8192) {
            errno = EOVERFLOW;
            return -1;
        }
    }
    if (delimiter == NULL || strncmp((char *)response, "HTTP/1.1 200 OK\r\n", 17) != 0) {
        errno = EPROTO;
        return -1;
    }
    const char *content_length = strstr((char *)response, "\r\nContent-Length: ");
    const char *request_id = strstr((char *)response,
                                    "\r\nX-OpenShield-Request-Id: ");
    const char *echoed_send_ns = strstr((char *)response,
                                        "\r\nX-OpenShield-Sent-Ns: ");
    if (content_length == NULL || content_length >= delimiter ||
        request_id == NULL || request_id >= delimiter ||
        echoed_send_ns == NULL || echoed_send_ns >= delimiter) {
        errno = EPROTO;
        return -1;
    }
    content_length += strlen("\r\nContent-Length: ");
    char *end = NULL;
    unsigned long parsed = strtoul(content_length, &end, 10);
    if (end == content_length || end[0] != '\r' || end[1] != '\n' ||
        parsed != response_size) {
        errno = EPROTO;
        return -1;
    }
    request_id += strlen("\r\nX-OpenShield-Request-Id: ");
    errno = 0;
    unsigned long long parsed_request_id = strtoull(request_id, &end, 10);
    if (errno != 0 || end == request_id || end[0] != '\r' || end[1] != '\n' ||
        parsed_request_id != 1ULL) {
        errno = EPROTO;
        return -1;
    }
    echoed_send_ns += strlen("\r\nX-OpenShield-Sent-Ns: ");
    errno = 0;
    unsigned long long parsed_send_ns = strtoull(echoed_send_ns, &end, 10);
    if (errno != 0 || end == echoed_send_ns || end[0] != '\r' ||
        end[1] != '\n' || parsed_send_ns != (unsigned long long)sent_ns) {
        errno = EPROTO;
        return -1;
    }
    size_t header_bytes = (size_t)(delimiter - (char *)response) + 4;
    const size_t expected = header_bytes + response_size;
    while (used < expected) {
        ssize_t received = recv(descriptor, response + used, expected - used, 0);
        if (received <= 0) {
            return -1;
        }
        used += (size_t)received;
    }
    return used == expected ? 0 : -1;
}

static int probe_udp(int descriptor, uint32_t response_size, uint64_t sent_ns) {
    uint8_t request[UDP_REQUEST_BYTES];
    memset(request, 0, sizeof(request));
    memcpy(request, "OSUF", 4);
    request[4] = 1;
    request[5] = 1;
    put_u32(request + 8, 0);
    put_u32(request + 12, response_size);
    put_u64(request + 16, 1);
    put_u64(request + 24, 1);
    put_u64(request + 32, sent_ns);
    if (send(descriptor, request, sizeof(request), 0) != (ssize_t)sizeof(request)) {
        return -1;
    }
    uint8_t response[UDP_RESPONSE_BYTES + MAX_RESPONSE_BYTES];
    ssize_t received = recv(descriptor, response, sizeof(response), 0);
    if (received < 0) {
        return -1;
    }
    if (received != (ssize_t)(UDP_RESPONSE_BYTES + response_size) ||
        memcmp(response, "OSUR", 4) != 0 || response[4] != 1 ||
        response[5] != 0 || get_u32(response + 8) != response_size ||
        get_u64(response + 12) != 1 || get_u64(response + 20) != 1 ||
        get_u64(response + 28) != sent_ns) {
        errno = EPROTO;
        return -1;
    }

    /*
     * Close the workload protocol cleanly. The UDP server retains per-flow
     * sequence state until a drain barrier proves that every preceding
     * datagram arrived. Without this exchange each successful liveness probe
     * was reported as an incomplete flow and a server protocol error.
     */
    const uint64_t barrier_sent_ns = monotonic_ns();
    memset(request, 0, sizeof(request));
    memcpy(request, "OSUF", 4);
    request[4] = 1;
    request[5] = 2;
    put_u64(request + 16, 1);
    put_u64(request + 24, 2);
    put_u64(request + 32, barrier_sent_ns);
    if (send(descriptor, request, sizeof(request), 0) != (ssize_t)sizeof(request)) {
        return -1;
    }
    received = recv(descriptor, response, sizeof(response), 0);
    if (received != UDP_RESPONSE_BYTES || memcmp(response, "OSUR", 4) != 0 ||
        response[4] != 1 || response[5] != 0 || get_u32(response + 8) != 0 ||
        get_u64(response + 12) != 1 || get_u64(response + 20) != 2 ||
        get_u64(response + 28) != barrier_sent_ns) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static void emit_result(const char *transport, const char *protocol, bool success,
                        uint64_t elapsed_ns, int error_number) {
    printf("{\"schema\":\"openshield.perf.workload.v1\",\"event\":\"probe\","
           "\"role\":\"identity_probe\",\"transport\":\"%s\","
           "\"protocol\":\"%s\",\"success\":%s,\"errno\":%d,"
           "\"latency_ms\":%.6f}\n",
           transport, protocol, success ? "true" : "false", error_number,
           (double)elapsed_ns / 1000000.0);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 6) {
        fprintf(stderr,
                "usage: %s tcp|tcp-framed|udp NUMERIC_HOST PORT [TIMEOUT_MS] "
                "[RESPONSE_BYTES]\n",
                argv[0]);
        return EXIT_USAGE_ERROR;
    }
    const bool is_udp = strcmp(argv[1], "udp") == 0;
    const bool is_http = strcmp(argv[1], "tcp") == 0;
    const bool is_framed = strcmp(argv[1], "tcp-framed") == 0;
    if (!is_udp && !is_http && !is_framed) {
        return EXIT_USAGE_ERROR;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return EXIT_PROBE_FAILED;
    }
    unsigned long port = 0;
    unsigned long timeout_ms = 1000;
    unsigned long response_size = 32;
    if (!parse_bounded(argv[3], 1, 65535, &port) ||
        (argc >= 5 && !parse_bounded(argv[4], MIN_TIMEOUT_MS, MAX_TIMEOUT_MS,
                                    &timeout_ms)) ||
        (argc >= 6 && !parse_bounded(argv[5], 0, MAX_RESPONSE_BYTES,
                                    &response_size))) {
        return EXIT_USAGE_ERROR;
    }
    (void)port;
    const uint64_t started_ns = monotonic_ns();
    const int descriptor = connect_numeric(argv[2], argv[3],
                                           is_udp ? SOCK_DGRAM : SOCK_STREAM,
                                           timeout_ms);
    if (descriptor < 0) {
        const int saved_error = errno;
        emit_result(is_udp ? "udp" : "tcp",
                    is_udp ? "framed" : (is_http ? "http1" : "framed"), false,
                    monotonic_ns() - started_ns, saved_error);
        return EXIT_PROBE_FAILED;
    }
    const uint64_t sent_ns = monotonic_ns();
    int result = is_udp
                     ? probe_udp(descriptor, (uint32_t)response_size, sent_ns)
                     : (is_http ? probe_tcp_http(descriptor, argv[2],
                                                 (uint32_t)response_size, sent_ns)
                                : probe_tcp_framed(descriptor,
                                                   (uint32_t)response_size,
                                                   sent_ns));
    const int saved_error = result == 0 ? 0 : errno;
    close(descriptor);
    emit_result(is_udp ? "udp" : "tcp",
                is_udp ? "framed" : (is_http ? "http1" : "framed"), result == 0,
                monotonic_ns() - started_ns, saved_error);
    return result == 0 ? EXIT_SUCCESS : EXIT_PROBE_FAILED;
}
