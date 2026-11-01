# Source only inside the owning Bash executor at its paused execution boundary.
# The subshell and positional scratch space do not overwrite target variables.
caushell_frame_value() (
    case "$1" in
        _|BASHPID|BASH_SUBSHELL|BASH_COMMAND|BASH_LINENO|FUNCNAME|BASH_ARGV|BASH_ARGC|LINENO|RANDOM|SRANDOM|SECONDS|EPOCHSECONDS|EPOCHREALTIME)
            builtin printf 'unknown\0\0'; exit ;;
    esac
    if ! builtin declare -p "$1" >/dev/null 2>&1; then
        builtin printf 'absent\0\0'; exit
    fi
    set -- "$1" "$2" "$(builtin declare -p "$1" 2>/dev/null)"
    if [[ $2 == environment && ! $3 =~ ^declare\ -[^\ ]*x[^\ ]*\  ]]; then
        builtin printf 'absent\0\0'
    elif [[ $3 =~ ^declare\ -[^\ ]*[aAn][^\ ]*\  ]]; then
        builtin printf 'unknown\0\0'
    else
        builtin printf 'present\0%s\0' "${!1}"
    fi
)

caushell_frame_integer() (
    set -- "$(builtin declare -p "$1" 2>/dev/null)"
    if [[ $1 =~ ^declare\ -[^\ ]*i[^\ ]*\  && ! $1 =~ ^declare\ -[^\ ]*[aAn][^\ ]*\  && $1 == *=* && $1 != *'=""' ]]; then
        builtin printf '1\0'
    else
        builtin printf '0\0'
    fi
)

caushell_frame_capture() (
    # $1 is a private correlation nonce, remaining arguments are planned names.
    [[ $1 =~ ^[a-f0-9]{32}$ && $# -le 129 ]] || exit 64
    # Validation uses positional iteration below, in a separate subshell so a
    # requested environment variable named "name" is not shadowed by scratch.
    (
        shift
        while (( $# )); do
            [[ $1 =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ && ${#1} -le 256 ]] || exit 64
            shift
        done
    ) || exit 64
    builtin printf 'caushell-bash-frame-v1\0%s\0' "$1"
    if [[ $- == *f* ]]; then builtin printf '1\0'; else builtin printf '0\0'; fi
    # This helper's positional arguments never become target Shell variables.
    caushell_frame_flags() (
        while (( $# )); do
            if builtin shopt -q "$1" 2>/dev/null; then
                builtin printf '1\0'
            else
                builtin printf '0\0'
            fi
            shift
        done
    )
    caushell_frame_flags nullglob failglob dotglob nocaseglob globstar extglob globskipdots
    caushell_frame_value GLOBIGNORE shell
    caushell_frame_value LC_ALL shell
    caushell_frame_value LC_COLLATE shell
    caushell_frame_value LC_CTYPE shell
    caushell_frame_value LANG shell
    shift
    while (( $# )); do
        builtin printf '%s\0' "$1"
        caushell_frame_value "$1" environment
        shift
    done
    builtin printf 'END\0'
)

# nonce, environment count, environment names, then partial shell scalar names.
# The separate channel must never promote unexported values into child env.
caushell_frame_capture_plan() (
    [[ $2 =~ ^[0-9]+$ && $2 -le 128 && $# -ge $((2+$2)) && $# -le $((130+$2)) ]] || exit 64
    caushell_frame_capture "$1" "${@:3:$2}" || exit 64
    shift "$((2+$2))"
    if (( $# )); then
        builtin printf 'caushell-shell-scalars-v2\0'
        while (( $# )); do
            [[ $1 =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ && ${#1} -le 256 ]] || exit 64
            builtin printf '%s\0' "$1"
            caushell_frame_integer "$1"
            caushell_frame_value "$1" shell
            shift
        done
        builtin printf 'END\0'
    fi
)
