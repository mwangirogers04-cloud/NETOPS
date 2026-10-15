#!/usr/bin/env bash
# NETOPS Service Manager
set -e

ACTION="${1:-status}"

case "$ACTION" in
    start)
        echo "Starting NETOPS services..."
        sudo systemctl start netops-backend netops-frontend netops-agent
        echo "Services started."
        ;;
    stop)
        echo "Stopping NETOPS services..."
        sudo systemctl stop netops-frontend netops-backend netops-agent
        echo "Services stopped."
        ;;
    restart)
        echo "Restarting NETOPS services..."
        sudo systemctl restart netops-backend netops-frontend netops-agent
        echo "Services restarted."
        ;;
    status)
        echo "=== NETOPS Services Status ==="
        systemctl status netops-backend netops-frontend netops-agent --no-pager
        ;;
    logs)
        SERVICE="${2:-backend}"
        sudo journalctl -u "netops-${SERVICE}" -f
        ;;
    open)
        xdg-open http://localhost:5173 2>/dev/null || sensible-browser http://localhost:5173
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs [backend|frontend|agent]|open}"
        exit 1
        ;;
esac
