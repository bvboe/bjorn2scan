#!/bin/bash
# Helper script to build and run the bjorn2scan-agent test container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="bjorn2scan-agent:test-local"
CONTAINER_NAME="bjorn2scan-test"

show_help() {
    cat << EOF
Usage: $0 <command>

Commands:
    build       Build the test container image
    run         Build and run the test container
    stop        Stop the running test container
    logs        Show logs from the test container
    shell       Open a shell in the running container
    restart     Restart the agent service in the container
    clean       Stop and remove the container
    help        Show this help message

Examples:
    $0 build                    # Build the image
    $0 run                      # Build and run (will stop existing container)
    $0 shell                    # Get a bash shell in the running container
    $0 logs                     # Follow the logs
    $0 restart                  # Restart the agent service

The container runs with:
- systemd as init system (PID 1)
- Docker daemon running inside
- bjorn2scan-agent installed and running
- Agent accessible at http://localhost:9999

EOF
}

build() {
    echo "Building test container image..."
    echo "Note: Building from parent directory to include scanner-core"
    cd "$SCRIPT_DIR/.."
    docker build -f bjorn2scan-agent/Dockerfile.test -t "$IMAGE_NAME" .
    echo "✓ Image built: $IMAGE_NAME"
}

stop_existing() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "Stopping and removing existing container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi
}

run() {
    build
    stop_existing

    echo ""
    echo "Starting test container..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        --privileged \
        --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -p 9999:9999 \
        "$IMAGE_NAME"

    echo ""
    echo "Waiting for container to be ready..."
    sleep 5

    # Wait for health check
    for i in {1..30}; do
        if docker exec "$CONTAINER_NAME" curl -sf http://localhost:9999/health > /dev/null 2>&1; then
            echo "✓ Container is healthy!"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "⚠ Health check timeout (container may still be starting)"
        fi
        sleep 2
    done

    echo ""
    echo "=========================================="
    echo "Test container is running!"
    echo "=========================================="
    echo "Container name: $CONTAINER_NAME"
    echo "Agent URL:      http://localhost:9999"
    echo ""
    echo "Quick test:"
    echo "  curl http://localhost:9999/health"
    echo ""
    echo "View logs:"
    echo "  $0 logs"
    echo ""
    echo "Open shell:"
    echo "  $0 shell"
    echo ""
    echo "Check agent status:"
    echo "  docker exec $CONTAINER_NAME systemctl status bjorn2scan-agent"
    echo ""
}

stop() {
    echo "Stopping container..."
    docker stop "$CONTAINER_NAME"
    echo "✓ Container stopped"
}

logs() {
    docker logs -f "$CONTAINER_NAME"
}

shell() {
    docker exec -it "$CONTAINER_NAME" /bin/bash
}

restart_agent() {
    echo "Restarting bjorn2scan-agent service..."
    docker exec "$CONTAINER_NAME" systemctl restart bjorn2scan-agent
    sleep 2
    docker exec "$CONTAINER_NAME" systemctl status bjorn2scan-agent --no-pager
}

clean() {
    stop_existing
    echo "✓ Container removed"
}

# Main command dispatcher
case "${1:-help}" in
    build)
        build
        ;;
    run)
        run
        ;;
    stop)
        stop
        ;;
    logs)
        logs
        ;;
    shell)
        shell
        ;;
    restart)
        restart_agent
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
