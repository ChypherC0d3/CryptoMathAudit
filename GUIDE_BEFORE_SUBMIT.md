# GUIA OBLIGATORIA ANTES DE SUBMITEAR UN BUG BOUNTY

## REGLA #1: NUNCA SALIRSE DEL SCOPE

Antes de escribir una sola linea del report, verificar:

### Checklist pre-submit (OBLIGATORIO):

1. [ ] **Descargar la lista ACTUALIZADA de assets in-scope**
   - URL: `https://immunefi.com/bug-bounty/[PROGRAMA]/scope/`
   - Guardar copia local en `F:\Claude\BugBounty\bounties\[programa]\scope_assets.txt`
   - Fecha de descarga anotada

2. [ ] **Verificar que el contrato afectado esta EXACTAMENTE en la lista**
   - Buscar la address exacta del contrato
   - Si el bug esta en un contrato NO listado = OUT OF SCOPE = RECHAZO
   - Si el bug esta en una implementacion detras de un proxy listado = verificar que el proxy esta in-scope

3. [ ] **Verificar que el impacto esta in-scope**
   - Leer la seccion "Impacts in Scope" del programa
   - El impacto que seleccionamos DEBE estar listado
   - Si no esta = OUT OF SCOPE = RECHAZO

4. [ ] **Verificar reglas especificas del programa**
   - Leer TODAS las reglas custom del programa
   - Buscar exclusiones especificas (ej: "known issues", "won't fix")
   - Verificar si requieren PoC ejecutable o solo descripcion

5. [ ] **Verificar que NO es un issue conocido**
   - Buscar en GitHub issues del proyecto
   - Buscar auditorias previas
   - Si el bug ya fue reportado = DUPLICADO = RECHAZO

6. [ ] **PoC debe ser COMPLETO y EJECUTABLE**
   - Foundry test que se puede correr con `forge test`
   - Instrucciones paso a paso
   - No solo teoria — codigo que DEMUESTRA el bug

## REGLA #2: ACTUALIZAR LA BASE DE CONOCIMIENTO

Antes de empezar a investigar un target:

1. Descargar scope actualizado
2. Guardar en `F:\Claude\BugBounty\bounties\[programa]\`
3. Listar TODOS los contratos in-scope
4. Identificar cuales son proxies vs implementaciones
5. Mapear que tipo de bugs aplican a cada contrato

## REGLA #3: PRIORIZAR LA INVESTIGACION

Orden de trabajo:
1. Scope analysis (que esta in-scope?)
2. Architecture mapping (como se conectan los contratos?)
3. Vulnerability hunting (buscar bugs)
4. PoC development (demostrar el bug)
5. Report writing (escribir el report)
6. FINAL CHECK contra esta guia
7. Submit

## ERRORES COMUNES A EVITAR

- [ ] Seleccionar un asset que NO esta en la lista de scope
- [ ] Reclamar un impacto que no aplica al tipo de contrato
- [ ] Submitear sin PoC funcional
- [ ] No leer las reglas custom del programa
- [ ] Asumir que un contrato esta in-scope sin verificar
- [ ] No verificar si el bug ya fue reportado

## LECCION APRENDIDA (Hyperlane - Marzo 2026)

**Error**: Encontramos bug real en WeightedMultisigIsm pero el contrato
NO estaba en la lista de 222 assets in-scope de Hyperlane.

**Resultado**: Report cerrado automaticamente por Immunefi.

**Leccion**: SIEMPRE verificar la address exacta del contrato contra
la lista de scope ANTES de escribir el report.
