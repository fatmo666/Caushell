# Sourced at the actual Bash action boundary, after the native CLI's prologue.
# Args: endpoint ticket nonce private-status-name previous-status argc observer-argv... names...
[[ -n ${BASH_VERSION-} && $4 =~ ^__caushell_status_[a-f0-9]{32}$ && $5 =~ ^[0-9]+$ && $5 -le 255 && $6 =~ ^[0-9]+$ && $6 -ge 1 && $6 -le 32 ]] || return 125
! builtin declare -p "$4" >/dev/null 2>&1 || return 125
builtin printf -v "$4" '%s' "$5" || return 125
# Scratch variables and helper definitions exist only in forked copies of this
# exact paused frame. The task's positional parameters, variables and stdin survive.
(
    builtin source "${BASH_SOURCE[0]%/*}/capture.bash" || exit 125
    builtin printf 'caushell-owning-context-v1\0'
    caushell_frame_value HOME shell
    if [[ ${@:$((7+$6)):1} == --native-v1 ]]; then
        caushell_frame_capture_extended "$3" "${@:$((8+$6))}"
    else caushell_frame_capture_plan "$3" "${@:$((7+$6))}"; fi
) | (
    set -- "$1" "$2" "$3" "$(builtin pwd -P)" "$6" "${@:7}"
    exec "${@:6:$5}" frame-submit "$1" "$2" "$3" "$4"
)
