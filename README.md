# 🛡️ CrowdStrike Falcon NGSIEM: Advanced Search Library

Este repositorio contiene una colección de consultas (queries) optimizadas para **CrowdStrike Falcon Next-Gen SIEM (LogScale)**. Están diseñadas para facilitar tareas de *Threat Hunting*, auditoría de cumplimiento y respuesta ante incidentes.

---

## 📊 Consultas de Investigación (LQL)

### 1. Control de Conexiones en Puertos Críticos
Identifica IPs remotas que intentan establecer conexiones a través de protocolos comunes de administración o navegación. Útil para detectar movimientos laterales.

```kusto
// Revisión de IPs conectadas por HTTP, SSH o RDP
ComputerName = "XXXXXX" 
| #event_simpleName = "NetworkConnectIP4"
| RemotePort = /(80|3389|22)/
| groupBy([RemoteAddressIP4], function=[count(as=count)])
| sort([count], order=desc, limit=1000)

2. Auditoría de Logons por Usuario
Analiza el comportamiento de un usuario en un equipo específico, desglosando el tipo de inicio de sesión (LogonType) y las direcciones IP involucradas.

// Conexiones remotas más comunes de un usuario
ComputerName = "XXXXXXXXX"
UserName = "XXXXXXXXX"
| groupBy([ComputerName, UserName, LogonType, LocalIP, RemoteIP], function=[count(as=count)])
| sort([count], order=desc)

3. Historial de Comandos Ejecutados
Extrae una línea de tiempo de la actividad en consola. Incluye el formateo de tiempo para la zona horaria de España/Europa.

// Comandos ejecutados en un espacio de tiempo determinado
ComputerName = "XXXXXXXXXXX" 
| #event_simpleName = "CommandHistory"
| time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, locale=es_ES, timezone="Europe/Madrid")
| table([time, UserName, CommandHistory, CommandLine, ImageFileName, TargetProcessId])
| sort([time], order=desc)

4. Monitorización de Tareas Programadas
Rastrea la persistencia mediante la creación, modificación o eliminación de tareas en el sistema.
// Revisión de tareas modificadas, registradas y eliminadas
ComputerName = "XXXXXXXXXX"
| #event_simpleName = /ScheduledTask/
| time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, locale=es_ES, timezone="Europe/Madrid")
| table([time, #event_simpleName, UserName, TaskAuthor, TaskExecArguments, TaskExecCommand, TaskName, @rawstring], limit=20000)
| sort([time], order=desc)

5. Análisis de Tráfico DNS
Valida si un equipo está resolviendo dominios o subdominios específicos. Muy útil para detectar indicadores de compromiso (IOCs).
// Validación de conexiones a un dominio/subdominio
ComputerName = "XXXXXXXXXXXXXXXX"
| #event_simpleName  = "DnsRequest"
| DomainName = /google/i  // Puedes cambiar 'google' por el IOC que busques
| groupBy([DomainName], function=[count(as=count)])
| sort([count], order=desc, limit=10000)
