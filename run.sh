#!/bin/bash
cd /var/www/html/escanerpentest
set -a
source .env
set +a
exec ./agente-seguridad
