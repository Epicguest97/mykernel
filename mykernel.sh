#!/bin/bash

# Advanced Shell Kernel Simulator

# Kernel Configuration
KERNEL_VERSION="0.2.0"
KERNEL_NAME="ShellOS"

# Directories
KERNEL_HOME="/tmp/shellos"
PROC_DIR="$KERNEL_HOME/proc"
LOG_DIR="$KERNEL_HOME/log"
IPC_DIR="$KERNEL_HOME/ipc"

# Logging and Configuration
KERNEL_LOG="$LOG_DIR/kernel.log"
CONFIG_FILE="$KERNEL_HOME/kernel.conf"

# Process Management Enhanced
declare -A PROCESS_TABLE
declare -A PROCESS_PRIORITY
declare -A PROCESS_STATE
declare -A PROCESS_MEMORY
declare -A PROCESS_PARENT
declare -A PROCESS_CHILDREN

# Resource Limits
MAX_PROCESSES=64
MAX_MEMORY=$((4 * 1024 * 1024))  # 4GB simulated memory
CURRENT_MEMORY=0
NEXT_PID=1

# Scheduling
SCHEDULING_ALGORITHM="round_robin"
TIME_QUANTUM=100  # milliseconds

# Security
declare -A PROCESS_USER
CURRENT_USER="root"

# Enhanced Logging Function
log() {
    local level="${2:-INFO}"
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$KERNEL_LOG"
}

# Memory Management
allocate_memory() {
    local pid="$1"
    local size="${2:-1024}"  # Default 1KB

    if ((CURRENT_MEMORY + size > MAX_MEMORY)); then
        log "Memory allocation failed for PID $pid: Out of memory" "ERROR"
        return 1
    fi

    PROCESS_MEMORY[$pid]=$size
    ((CURRENT_MEMORY += size))
    return 0
}

free_memory() {
    local pid="$1"
    local size="${PROCESS_MEMORY[$pid]:-0}"

    ((CURRENT_MEMORY -= size))
    unset PROCESS_MEMORY[$pid]
}

# Advanced Process Creation
create_process() {
    local command="$1"
    local parent_pid="${2:-0}"
    local priority="${3:-50}"  # Default priority
    local user="${4:-$CURRENT_USER}"

    # Check process limit
    if ((${#PROCESS_TABLE[@]} >= MAX_PROCESSES)); then
        log "Cannot create process: Maximum processes reached" "ERROR"
        return 1
    fi

    # Allocate memory
    if ! allocate_memory "$NEXT_PID"; then
        return 1
    fi

    # Create process directory
    mkdir -p "$PROC_DIR/$NEXT_PID"

    # Process Details
    PROCESS_TABLE[$NEXT_PID]="$command"
    PROCESS_PRIORITY[$NEXT_PID]=$priority
    PROCESS_STATE[$NEXT_PID]="READY"
    PROCESS_USER[$NEXT_PID]="$user"
    PROCESS_PARENT[$NEXT_PID]="$parent_pid"

    # Track parent-child relationship
    if ((parent_pid > 0)); then
        PROCESS_CHILDREN[$parent_pid]+=" $NEXT_PID"
    fi

    # Background execution with process group
    setsid bash -c "$command" &
    local pid=$!

    # Update process state
    PROCESS_STATE[$NEXT_PID]="RUNNING"

    log "Created process PID $NEXT_PID: $command (Priority: $priority, User: $user)" "PROCESS"

    # Increment PID
    ((NEXT_PID++))

    return 0
}

# Round Robin Scheduler
round_robin_schedule() {
    local pids=("${!PROCESS_STATE[@]}")
    local current_index=0

    while true; do
        if ((${#pids[@]} == 0)); then
            log "No processes to schedule" "WARNING"
            sleep 1
            continue
        fi

        local pid="${pids[$current_index]}"

        # Skip terminated processes
        if [[ "${PROCESS_STATE[$pid]}" == "TERMINATED" ]]; then
            unset PROCESS_STATE[$pid]
            continue
        fi

        # Simulate time slice
        kill -SIGCONT "$pid" 2>/dev/null
        sleep $(echo "$TIME_QUANTUM/1000" | bc -l)
        kill -SIGSTOP "$pid" 2>/dev/null

        # Move to next process
        ((current_index = (current_index + 1) % ${#pids[@]}))
    done
}

# Inter-Process Communication (Simple Message Passing)
send_message() {
    local sender_pid="$1"
    local receiver_pid="$2"
    local message="$3"

    # Create IPC directory if not exists
    mkdir -p "$IPC_DIR"

    # Write message to receiver's mailbox
    echo "$sender_pid:$message" >> "$IPC_DIR/pid_$receiver_pid.mbox"
    log "Message sent from PID $sender_pid to PID $receiver_pid" "IPC"
}

receive_message() {
    local receiver_pid="$1"
    local mailbox="$IPC_DIR/pid_$receiver_pid.mbox"

    if [[ -f "$mailbox" ]]; then
        cat "$mailbox"
        rm "$mailbox"
    else
        log "No messages for PID $receiver_pid" "IPC"
    fi
}

# System Call Simulation
system_call() {
    local call_type="$1"
    shift

    case "$call_type" in
        "create_process")
            create_process "$@"
            ;;
        "kill_process")
            local pid="$1"
            kill "$pid"
            PROCESS_STATE[$pid]="TERMINATED"
            free_memory "$pid"
            log "Process $pid terminated" "PROCESS"
            ;;
        "send_message")
            send_message "$@"
            ;;
        "receive_message")
            receive_message "$@"
            ;;
        *)
            log "Unknown system call: $call_type" "ERROR"
            return 1
            ;;
    esac
}

# Kernel Panic Handler
kernel_panic() {
    local error_message="$1"
    log "KERNEL PANIC: $error_message" "CRITICAL"
    
    # Attempt emergency shutdown
    log "Attempting emergency shutdown..." "CRITICAL"
    for pid in "${!PROCESS_STATE[@]}"; do
        kill -9 "$pid" 2>/dev/null
    done

    # Clean up resources
    rm -rf "$KERNEL_HOME"

    echo "Kernel Panic: System Halted"
    exit 1
}

# Initialization
initialize_kernel() {
    # Create kernel directories
    mkdir -p "$KERNEL_HOME" "$PROC_DIR" "$LOG_DIR" "$IPC_DIR"

    # Create configuration file
    cat > "$CONFIG_FILE" << EOL
KERNEL_VERSION=$KERNEL_VERSION
KERNEL_NAME=$KERNEL_NAME
MAX_PROCESSES=$MAX_PROCESSES
MAX_MEMORY=$MAX_MEMORY
SCHEDULING_ALGORITHM=$SCHEDULING_ALGORITHM
EOL

    # Log kernel start
    log "Kernel $KERNEL_NAME v$KERNEL_VERSION initialized" "INFO"
}

# Interactive Kernel Shell
kernel_shell() {
    while true; do
        read -p "kernel> " command args

        case "$command" in
            "ps")
                for pid in "${!PROCESS_TABLE[@]}"; do
                    echo "PID: $pid | Command: ${PROCESS_TABLE[$pid]} | State: ${PROCESS_STATE[$pid]} | Priority: ${PROCESS_PRIORITY[$pid]}"
                done
                ;;
            "run")
                system_call create_process "$args"
                ;;
            "kill")
                system_call kill_process "$args"
                ;;
            "msg")
                # Usage: msg send <sender_pid> <receiver_pid> <message>
                # Usage: msg receive <receiver_pid>
                subcmd="$1"
                shift
                if [[ "$subcmd" == "send" ]]; then
                    system_call send_message "$@"
                elif [[ "$subcmd" == "receive" ]]; then
                    system_call receive_message "$@"
                fi
                ;;
            "memory")
                echo "Used Memory: $CURRENT_MEMORY / $MAX_MEMORY KB"
                ;;
            "exit")
                log "Kernel shutting down" "INFO"
                break
                ;;
            *)
                echo "Unknown command. Available: ps, run, kill, msg, memory, exit"
                ;;
        esac
    done
}

# Trap signals
trap 'kernel_panic "Received critical system signal"' SIGINT SIGTERM

# Kernel Main Function
main() {
    # Initialize kernel environment
    initialize_kernel

    # Start background scheduler
    round_robin_schedule &
    local scheduler_pid=$!

    # Start interactive shell
    kernel_shell

    # Clean up
    kill "$scheduler_pid"
    rm -rf "$KERNEL_HOME"
}

# Execute kernel
main