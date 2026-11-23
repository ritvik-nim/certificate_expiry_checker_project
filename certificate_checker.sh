#!/usr/bin/env bash
set -u

WARN_DAYS=30
DOMAINS_FILE=""
CSV_FILE=""
TIMEOUT_SEC=5
DOMAINS=()

usage() {
    cat << 'EOF'
Usage: ./certificate_checker.sh [-f file] [-w days] [-o file.csv] [-h] [domain[:port] ...]

Options:
  -f <file>      Read target domains from a file (one per line; '#' comments supported)
  -w <days>      Warning threshold in days before expiry (default: 30)
  -o <file.csv>  Write results to a CSV file
  -h             Show this help message
EOF
    exit 0
}

while getopts ":f:w:o:h" opt; do
    case "$opt" in
        f) DOMAINS_FILE="$OPTARG" ;;
        w) WARN_DAYS="$OPTARG" ;;
        o) CSV_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

if ! [[ "$WARN_DAYS" =~ ^[0-9]+$ ]]; then
    echo "Error: Warning days (-w) must be a non-negative integer." >&2
    exit 1
fi

for d in "$@"; do
    [[ -n "$d" ]] && DOMAINS+=("$d")
done

if [[ -n "$DOMAINS_FILE" ]]; then
    if [[ ! -f "$DOMAINS_FILE" ]]; then
        echo "Error: File '$DOMAINS_FILE' not found." >&2
        exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d '\r' | xargs)"
        [[ -n "$line" ]] && DOMAINS+=("$line")
    done < "$DOMAINS_FILE"
elif [[ ${#DOMAINS[@]} -eq 0 && -f "demo.txt" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d '\r' | xargs)"
        [[ -n "$line" ]] && DOMAINS+=("$line")
    done < "demo.txt"
fi

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    usage
fi

run_with_timeout() {
    local secs="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    else
        "$@"
    fi
}

fetch_not_after() {
    local host="$1"
    local port="$2"
    local cert_out enddate_line

    cert_out="$(
        printf 'Q\n' | run_with_timeout "$TIMEOUT_SEC" \
            openssl s_client -showcerts -servername "$host" -connect "${host}:${port}" 2>/dev/null \
            | awk '/BEGIN CERTIFICATE/{flag=1; print; next} /END CERTIFICATE/{print; flag=0; exit} flag{print}'
    )"

    [[ -z "$cert_out" ]] && return 1

    enddate_line="$(printf '%s\n' "$cert_out" | openssl x509 -noout -enddate 2>/dev/null)"
    [[ -z "$enddate_line" ]] && return 1

    printf '%s\n' "$enddate_line" \
        | grep -oE 'notAfter=.+' \
        | sed 's/^notAfter=//'
}

parse_expiry_epoch() {
    local raw="$1"
    local ep=""

    # Primary Linux / GNU date -d path
    ep="$(date -u -d "$raw" +%s 2>/dev/null)" && [[ -n "$ep" ]] && {
        printf '%s\n' "$ep"
        return 0
    }

    # macOS / BSD date fallback
    local clean_date
    clean_date="$(printf '%s' "$raw" | sed -E 's/[[:space:]]+(GMT|UTC)$//')"
    ep="$(date -u -j -f "%b %d %H:%M:%S %Y" "$clean_date" +%s 2>/dev/null)" && [[ -n "$ep" ]] && {
        printf '%s\n' "$ep"
        return 0
    }

    return 1
}

now_epoch="$(date -u +%s)"

printf "%-26s %-26s %-10s %-12s\n" "DOMAIN" "EXPIRY (UTC)" "DAYS LEFT" "STATUS"
printf "%-26s %-26s %-10s %-12s\n" "------" "------------" "---------" "------"

if [[ -n "$CSV_FILE" ]]; then
    printf "domain,expiry_utc,days_left,status\n" > "$CSV_FILE"
fi

for entry in "${DOMAINS[@]}"; do
    host="$entry"
    port="443"

    if [[ "$entry" == *:* ]]; then
        host="${entry%%:*}"
        port="${entry##*:}"
    fi

    if [[ -z "$host" || ! "$port" =~ ^[0-9]+$ ]]; then
        expiry_raw="N/A"
        days_left="-"
        status="PARSE_ERR"
    else
        expiry_raw="$(fetch_not_after "$host" "$port")"
        if [[ -z "$expiry_raw" ]]; then
            expiry_raw="N/A"
            days_left="-"
            status="UNREACHABLE"
        else
            expiry_epoch="$(parse_expiry_epoch "$expiry_raw")"
            if [[ -z "$expiry_epoch" ]]; then
                days_left="-"
                status="PARSE_ERR"
            else
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if (( days_left < 0 )); then
                    status="EXPIRED"
                elif (( days_left <= WARN_DAYS )); then
                    status="EXPIRING"
                else
                    status="OK"
                fi
            fi
        fi
    fi

    printf "%-26s %-26s %-10s %-12s\n" "$entry" "$expiry_raw" "$days_left" "$status"
    if [[ -n "$CSV_FILE" ]]; then
        printf '"%s","%s","%s","%s"\n' "$entry" "$expiry_raw" "$days_left" "$status" >> "$CSV_FILE"
    fi
done
