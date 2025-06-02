// GATEWAY-TO-GATEWAY DEADLOCK DETECTION (FIXED)
// Query untuk mendeteksi deadlock yang terjadi akibat gateway yang terhubung langsung ke gateway lain

// 1. Menggunakan IntermediateNode yang menghubungkan gateway
MATCH (i:IntermediateNode)
WHERE i.is_gateway_connector = true
WITH i
MATCH (source) 
WHERE source.id = i.from_gateway
MATCH (target)
WHERE target.id = i.to_gateway
// Periksa kombinasi gateway yang berpotensi deadlock (AND Split ke XOR Join)
WITH i, source, target
WHERE (source.subtype = 'Parallel' AND source.direction = 'Diverging' AND 
      target.subtype = 'Exclusive' AND target.direction = 'Converging')
   OR (source.subtype = 'Inclusive' AND source.direction = 'Diverging' AND 
       target.subtype = 'Exclusive' AND target.direction = 'Converging')
// Set flag deadlock
SET i.potential_deadlock = true
RETURN source.name AS sourceGateway, 
       source.subtype AS sourceType,
       source.direction AS sourceDirection,
       target.name AS targetGateway, 
       target.subtype AS targetType,
       target.direction AS targetDirection,
       i.name AS intermediateNode,
       'Deadlock potensial - pola gateway yang tidak kompatibel' AS deadlockType;

// 2. Deteksi interlocking gateway (menggunakan intermediate nodes)
MATCH path = (i1:IntermediateNode)-[*1..5]->(i2:IntermediateNode)
WHERE i1.is_gateway_connector = true 
  AND i2.is_gateway_connector = true
  AND i1 <> i2
WITH i1, i2, path
MATCH (source1) WHERE source1.id = i1.from_gateway
MATCH (target1) WHERE target1.id = i1.to_gateway
MATCH (source2) WHERE source2.id = i2.from_gateway
MATCH (target2) WHERE target2.id = i2.to_gateway
// Deteksi pola interlocking
WHERE source1.id = target2.id AND source2.id = target1.id
SET i1.potential_deadlock = true, i2.potential_deadlock = true
RETURN source1.name AS gateway1, target1.name AS gateway2,
       source2.name AS gateway3, target2.name AS gateway4,
       i1.name AS intermediate1, i2.name AS intermediate2,
       'Interlocking gateway yang menyebabkan deadlock' AS deadlockType;