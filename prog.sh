#!/usr/bin/env bash
set -Eeuo pipefail

# Captura SIGINT para probar señales (kill builtin)
trap 'echo "[trap] SIGINT capturada, seguimos..."' INT

umask 022
orig="$PWD"
cd /tmp

tmp="rt_bash_$$"

# 1) Abrir archivo con redirección (openat + O_CREAT | O_WRONLY | O_TRUNC)
exec {out}> "$tmp.txt"
printf 'Linea 1: %s\n' "hola" >&"$out"
printf 'Linea 2: epoch=%(%s)T\n' -1 >&"$out"   # printf builtin con tiempo (bash)
# Cierra descriptor (close)
exec {out}>&-

# 2) Reabrir para lectura (openat + O_RDONLY) y leer con timeout (posible pselect/select interno)
exec {in}< "$tmp.txt"
IFS= read -r -t 0.2 -u "$in" line1 || true
echo "leido-1: $line1"
IFS= read -r -t 0.2 -u "$in" line2 || true
echo "leido-2: $line2"
exec {in}<&-

# 3) Prueba de stat mediante builtins ([[ -e ... ]])
if [[ -e "$tmp.txt" ]]; then
  echo "existe: $tmp.txt"
fi

# 4) Cambios de estado de proceso
cd "$orig"
umask 077

# 5) Señales: envío INT a mí mismo (builtin kill)
kill -s INT $$ || true

# 6) Generar fork+execve+wait4 a propósito (externo)
ls -l /proc/self/fd >/dev/null 2>&1 || true

# 7) Truncado por redirección
: > "/tmp/$tmp.empty"

# Limpieza (externo: fork/exec/wait4 de rm)
rm -f "/tmp/$tmp.txt" "/tmp/$tmp.empty" || true
