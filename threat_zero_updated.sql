-- =============================================
-- PROYECTO FINAL: ADMINISTRACIÓN DE BASES DE DATOS
-- PROYECTO: THREAT ZERO
-- PROFESORA: MC. Melissa Osuna Cárdenas
-- =============================================

DROP DATABASE IF EXISTS threat_zero;
CREATE DATABASE threat_zero;
USE threat_zero;

-- =============================================
-- 1. ESTRUCTURA DE TABLAS (DDL)
-- =============================================

CREATE TABLE empresas (
    codigo             VARCHAR(10)  PRIMARY KEY,
    nombre             VARCHAR(100) NOT NULL,
    cantidad_empleados INT,
    email              VARCHAR(100) NOT NULL UNIQUE,   -- login de la empresa
    contrasena         VARCHAR(255) NOT NULL           -- hash bcrypt
) ENGINE=InnoDB;

CREATE TABLE usuarios (
    id_usuario       INT AUTO_INCREMENT PRIMARY KEY,
    nombre           VARCHAR(50)  NOT NULL,
    mail_corporativo VARCHAR(100) NOT NULL UNIQUE,     -- login del empleado
    telefono         VARCHAR(15),
    contrasena       VARCHAR(255) NOT NULL,            -- hash bcrypt
    codigo_empresa   VARCHAR(10)  NOT NULL,
    FOREIGN KEY (codigo_empresa) REFERENCES empresas(codigo)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE preguntas (
    id_pregunta INT AUTO_INCREMENT PRIMARY KEY,
    pregunta    VARCHAR(150) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE respuestas (
    id_respuesta INT AUTO_INCREMENT PRIMARY KEY,
    respuesta    VARCHAR(150) NOT NULL,
    es_correcta  BOOLEAN DEFAULT FALSE,               -- indica la opción correcta
    id_pregunta  INT NOT NULL,
    FOREIGN KEY (id_pregunta) REFERENCES preguntas(id_pregunta)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE sugerencias (
    id_sugerencia INT AUTO_INCREMENT PRIMARY KEY,
    sugerencia    VARCHAR(200) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE diagnostico (
    id_diagnostico    INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario        INT NOT NULL,
    puntaje           INT DEFAULT 0,                  -- resultado del test (0-100)
    nivel_riesgo      ENUM('bajo','medio','alto','critico') DEFAULT 'alto',
    fecha_diagnostico TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE diagnostico_sugerencia (
    id_diagnostico INT NOT NULL,
    id_sugerencia  INT NOT NULL,
    PRIMARY KEY (id_diagnostico, id_sugerencia),
    FOREIGN KEY (id_diagnostico) REFERENCES diagnostico(id_diagnostico)
        ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (id_sugerencia)  REFERENCES sugerencias(id_sugerencia)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE log_seguridad (
    id_log         INT AUTO_INCREMENT PRIMARY KEY,
    tabla_afectada VARCHAR(50),
    accion         VARCHAR(50),
    usuario_bd     VARCHAR(50),
    fecha          DATETIME
) ENGINE=InnoDB;

-- =============================================
-- 2. LÓGICA DE NEGOCIO
-- =============================================

DELIMITER $$

-- FUNCIONES --

CREATE FUNCTION fn_validar_mail(correo VARCHAR(100))
RETURNS BOOLEAN DETERMINISTIC
BEGIN
    RETURN correo LIKE '%@%.%';
END $$

CREATE FUNCTION fn_total_empleados_empresa(cod_emp VARCHAR(10))
RETURNS INT DETERMINISTIC
BEGIN
    DECLARE total INT;
    SELECT COUNT(*) INTO total FROM usuarios WHERE codigo_empresa = cod_emp;
    RETURN total;
END $$

CREATE FUNCTION fn_nivel_riesgo(puntaje INT)
RETURNS VARCHAR(10) DETERMINISTIC
BEGIN
    DECLARE nivel VARCHAR(10);
    IF    puntaje >= 75 THEN SET nivel = 'critico';
    ELSEIF puntaje >= 50 THEN SET nivel = 'alto';
    ELSEIF puntaje >= 25 THEN SET nivel = 'medio';
    ELSE                      SET nivel = 'bajo';
    END IF;
    RETURN nivel;
END $$

-- PROCEDIMIENTOS --

CREATE PROCEDURE sp_reporte_empresa_detallado(IN cod_emp VARCHAR(10))
BEGIN
    SELECT
        u.nombre,
        u.mail_corporativo,
        u.telefono,
        e.nombre                AS empresa_nombre,
        COUNT(d.id_diagnostico) AS total_diagnosticos,
        MAX(d.puntaje)          AS ultimo_puntaje,
        MAX(d.nivel_riesgo)     AS nivel_riesgo
    FROM usuarios u
    JOIN empresas e ON u.codigo_empresa = e.codigo
    LEFT JOIN diagnostico d ON d.id_usuario = u.id_usuario
    WHERE e.codigo = cod_emp
    GROUP BY u.id_usuario, u.nombre, u.mail_corporativo, u.telefono, e.nombre;
END $$

CREATE PROCEDURE sp_registrar_diagnostico_completo(
    IN p_id_usuario    INT,
    IN p_puntaje       INT,
    IN p_id_sugerencia INT
)
BEGIN
    DECLARE v_nivel VARCHAR(10);
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    SET v_nivel = fn_nivel_riesgo(p_puntaje);

    START TRANSACTION;
        INSERT INTO diagnostico (id_usuario, puntaje, nivel_riesgo)
        VALUES (p_id_usuario, p_puntaje, v_nivel);

        INSERT INTO diagnostico_sugerencia (id_diagnostico, id_sugerencia)
        VALUES (LAST_INSERT_ID(), p_id_sugerencia);
    COMMIT;
END $$

-- TRIGGERS --

CREATE TRIGGER tr_audit_new_user
AFTER INSERT ON usuarios
FOR EACH ROW
BEGIN
    INSERT INTO log_seguridad (tabla_afectada, accion, usuario_bd, fecha)
    VALUES ('usuarios', 'INSERCIÓN NUEVO USUARIO', USER(), NOW());
END $$

CREATE TRIGGER tr_audit_new_empresa
AFTER INSERT ON empresas
FOR EACH ROW
BEGIN
    INSERT INTO log_seguridad (tabla_afectada, accion, usuario_bd, fecha)
    VALUES ('empresas', 'REGISTRO NUEVA EMPRESA', USER(), NOW());
END $$

CREATE TRIGGER tr_validar_borrado_pregunta
BEFORE DELETE ON preguntas
FOR EACH ROW
BEGIN
    IF (SELECT COUNT(*) FROM respuestas WHERE id_pregunta = OLD.id_pregunta) > 0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'No se puede borrar una pregunta que ya tiene respuestas asociadas';
    END IF;
END $$

DELIMITER ;

-- =============================================
-- 3. SEGURIDAD Y ROLES
-- =============================================

CREATE USER IF NOT EXISTS 'admin_tz'@'localhost'    IDENTIFIED BY 'Admin123!';
GRANT ALL PRIVILEGES ON threat_zero.* TO 'admin_tz'@'localhost';

CREATE USER IF NOT EXISTS 'operador_tz'@'localhost' IDENTIFIED BY 'Operador123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON threat_zero.* TO 'operador_tz'@'localhost';

CREATE USER IF NOT EXISTS 'auditor_tz'@'localhost'  IDENTIFIED BY 'Auditor123!';
GRANT EXECUTE ON threat_zero.* TO 'auditor_tz'@'localhost';
GRANT SELECT  ON threat_zero.log_seguridad TO 'auditor_tz'@'localhost';

FLUSH PRIVILEGES;

-- =============================================
-- 4. DATOS DE PRUEBA
-- =============================================
-- Las contraseñas en producción son hashes bcrypt generados por la app.
-- Estos INSERTs son para pruebas directas en Workbench.

INSERT INTO empresas (codigo, nombre, cantidad_empleados, email, contrasena) VALUES
('T01', 'Threat Zero Mazatlán', 10, 'admin@threatzeromzt.com', '$2b$10$HASH_EJEMPLO');

INSERT INTO usuarios (nombre, mail_corporativo, telefono, contrasena, codigo_empresa) VALUES
('Ramón López', 'ramon@threatzeromzt.com', '6691234567', '$2b$10$HASH_EJEMPLO', 'T01');

INSERT INTO preguntas (pregunta) VALUES
('¿Qué harías si recibes un correo de tu banco pidiendo verificar tu contraseña?'),
('¿Cuál de estas contraseñas es más segura?'),
('¿Qué es el ransomware?');

INSERT INTO respuestas (respuesta, es_correcta, id_pregunta) VALUES
('Hago clic en el enlace y verifico mis datos',           FALSE, 1),
('Llamo directamente al banco para confirmar',            TRUE,  1),
('Reenvío el correo a un compañero',                      FALSE, 1),
('password123',                                           FALSE, 2),
('M!k3_2024#xZ',                                          TRUE,  2),
('micontraseña',                                          FALSE, 2),
('Un virus que borra tus archivos',                       FALSE, 3),
('Software que cifra tus archivos y pide rescate',        TRUE,  3),
('Un programa que acelera tu PC',                         FALSE, 3);

INSERT INTO sugerencias (sugerencia) VALUES
('Nunca hagas clic en enlaces de correos no solicitados. Verifica siempre directamente con la institución.'),
('Usa contraseñas de al menos 12 caracteres combinando mayúsculas, números y símbolos.'),
('Mantén copias de seguridad de tus archivos en ubicaciones separadas.'),
('Activa la autenticación de dos factores en todas tus cuentas corporativas.'),
('Nunca conectes dispositivos USB desconocidos a equipos de la empresa.');

-- Prueba de objetos:
-- CALL sp_registrar_diagnostico_completo(1, 60, 1);
-- SELECT fn_nivel_riesgo(60);
-- CALL sp_reporte_empresa_detallado('T01');


-- =============================================
-- ACTUALIZACIÓN: Tabla sugerencias con nivel_riesgo
-- Ejecutar en MySQL Workbench sobre la BD threat_zero
-- =============================================

USE threat_zero;

-- 1. Agregar columna nivel_riesgo a sugerencias
ALTER TABLE sugerencias
  ADD COLUMN nivel_riesgo ENUM('bajo','medio','alto','critico') NOT NULL DEFAULT 'medio'
  AFTER sugerencia;

-- 2. Borrar las sugerencias genéricas anteriores (eran de prueba)
DELETE FROM sugerencias;

-- 3. Insertar sugerencias organizadas por nivel

-- ── NIVEL CRÍTICO ──
INSERT INTO sugerencias (sugerencia, nivel_riesgo) VALUES
('Implementar autenticación de dos factores (2FA) de forma obligatoria en todos los accesos corporativos de inmediato.', 'critico'),
('Realizar una auditoría de seguridad completa con un especialista externo en un plazo no mayor a 30 días.', 'critico'),
('Suspender temporalmente el acceso remoto hasta que se implementen políticas de VPN segura y cifrado.', 'critico'),
('Capacitar urgentemente al equipo en identificación de phishing — más del 75% de los ataques exitosos comienzan por correo.', 'critico'),
('Revisar y revocar permisos innecesarios de acceso a sistemas críticos siguiendo el principio de mínimo privilegio.', 'critico'),
('Instalar y configurar un sistema EDR (Endpoint Detection & Response) en todos los equipos de la empresa.', 'critico');

-- ── NIVEL ALTO ──
INSERT INTO sugerencias (sugerencia, nivel_riesgo) VALUES
('Establecer una política formal de contraseñas: mínimo 12 caracteres, rotación cada 90 días y sin reutilización.', 'alto'),
('Programar simulacros de phishing periódicos para que los empleados practiquen la detección de correos maliciosos.', 'alto'),
('Configurar copias de seguridad automáticas diarias con almacenamiento fuera de línea para prevenir ransomware.', 'alto'),
('Prohibir el uso de redes WiFi públicas sin VPN activa para empleados que trabajen de forma remota o híbrida.', 'alto'),
('Implementar una política de pantalla limpia: equipos bloqueados al ausentarse del puesto de trabajo.', 'alto'),
('Revisar los permisos de aplicaciones instaladas en equipos corporativos y desinstalar software no autorizado.', 'alto');

-- ── NIVEL MEDIO ──
INSERT INTO sugerencias (sugerencia, nivel_riesgo) VALUES
('Usar un gestor de contraseñas corporativo para evitar el uso de contraseñas débiles o repetidas entre servicios.', 'medio'),
('Activar las actualizaciones automáticas del sistema operativo y software en todos los equipos de la empresa.', 'medio'),
('Establecer un canal oficial para reportar incidentes o sospechas de ataque — los empleados deben saber a quién avisar.', 'medio'),
('Revisar la configuración de privacidad de las herramientas de colaboración (Teams, Slack, Drive) que usa la empresa.', 'medio'),
('Concientizar al equipo sobre los riesgos de ingeniería social: llamadas falsas, pretexting y suplantación de identidad.', 'medio'),
('Cifrar los discos duros de los equipos portátiles corporativos para proteger datos en caso de robo o pérdida.', 'medio');

-- ── NIVEL BAJO ──
INSERT INTO sugerencias (sugerencia, nivel_riesgo) VALUES
('¡Bien hecho! Mantén los buenos hábitos con revisiones de seguridad trimestrales para no bajar la guardia.', 'bajo'),
('Compartir las buenas prácticas del equipo con los nuevos empleados desde su primer día mediante un manual de onboarding.', 'bajo'),
('Considerar obtener una certificación de seguridad (ISO 27001 o similar) para formalizar y reconocer el buen trabajo.', 'bajo'),
('Documentar los procedimientos de respuesta a incidentes para actuar rápido si en algún momento ocurre un problema.', 'bajo'),
('Revisar periódicamente los registros de acceso a sistemas para detectar actividad inusual de forma proactiva.', 'bajo');

-- Verificar resultado
SELECT nivel_riesgo, COUNT(*) AS total FROM sugerencias GROUP BY nivel_riesgo;

select * from empresas;


-- =============================================
-- PREGUNTAS, RESPUESTAS Y NIVEL DE COMPROMISO — THREAT ZERO
-- Ejecutar en MySQL Workbench sobre threat_zero
-- =============================================

USE threat_zero;

-- 1. Agregar columna nivel_compromiso a respuestas
--    leve    = verde  (acción segura o error menor)
--    medio   = amarillo (riesgo moderado para la empresa)
--    critico = rojo   (compromete seriamente la seguridad)
ALTER TABLE respuestas
  ADD COLUMN nivel_compromiso ENUM('leve','medio','critico') NOT NULL DEFAULT 'medio'
  AFTER es_correcta;

-- 2. Limpiar datos anteriores
DELETE FROM respuestas;
DELETE FROM preguntas;
ALTER TABLE preguntas  AUTO_INCREMENT = 1;
ALTER TABLE respuestas AUTO_INCREMENT = 1;

-- ── PREGUNTAS ──
INSERT INTO preguntas (pregunta) VALUES
('¿Qué harías si recibes un correo de tu banco pidiendo verificar tu contraseña?'),
('¿Cuál de estas contraseñas es más segura?'),
('¿Qué es el ransomware?'),
('¿Qué debes hacer antes de conectarte a una red WiFi pública?'),
('Un compañero te pide tu contraseña por mensaje para "hacer una prueba urgente". ¿Qué haces?'),
('¿Cuál de estas acciones es más segura al usar el correo corporativo?'),
('¿Qué significa el candado 🔒 en la barra de direcciones del navegador?'),
('Recibes una llamada de "soporte técnico" pidiendo acceso remoto a tu equipo. ¿Qué haces?'),
('¿Con qué frecuencia deberías cambiar tu contraseña corporativa?'),
('¿Qué es el phishing?');

-- ── RESPUESTAS CON nivel_compromiso ──
-- Formato: (respuesta, es_correcta, nivel_compromiso, id_pregunta)

-- Pregunta 1: Correo del banco
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Hago clic en el enlace y verifico mis datos',             FALSE, 'critico', 1),
('Llamo directamente al banco para confirmar',              TRUE,  'leve',    1),
('Reenvío el correo a un compañero para que lo revise',     FALSE, 'medio',   1),
('Ignoro el correo sin reportarlo a nadie',                 FALSE, 'medio',   1);

-- Pregunta 2: Contraseñas
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('password123',                                             FALSE, 'critico', 2),
('M!k3_2024#xZ',                                           TRUE,  'leve',    2),
('micontraseña',                                           FALSE, 'critico', 2),
('123456789',                                              FALSE, 'critico', 2);

-- Pregunta 3: Ransomware
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Un virus que borra tus archivos permanentemente',         FALSE, 'medio',   3),
('Software que cifra tus archivos y pide rescate económico', TRUE, 'leve',   3),
('Un programa que acelera el rendimiento de tu PC',         FALSE, 'leve',   3),
('Una herramienta para recuperar archivos eliminados',      FALSE, 'leve',   3);

-- Pregunta 4: WiFi pública
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Conéctame directo, las redes públicas son seguras si tienen contraseña', FALSE, 'critico', 4),
('Usar una VPN antes de conectarme para cifrar mi tráfico', TRUE,  'leve',   4),
('Desactivar el antivirus para que la red no lo bloquee',  FALSE, 'critico', 4),
('No hace falta nada especial si solo voy a revisar el correo', FALSE, 'medio', 4);

-- Pregunta 5: Compañero pide contraseña
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Le doy la contraseña si conozco bien al compañero',       FALSE, 'critico', 5),
('Verifico por teléfono y si confirma, le mando la contraseña', FALSE, 'critico', 5),
('Me niego — nunca se comparten contraseñas, ni con compañeros de confianza', TRUE, 'leve', 5),
('Le doy solo los primeros 4 caracteres para que adivine el resto', FALSE, 'medio', 5);

-- Pregunta 6: Correo corporativo
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Usar el correo corporativo también para suscripciones personales', FALSE, 'medio',   6),
('Verificar el remitente antes de abrir adjuntos o hacer clic en enlaces', TRUE, 'leve', 6),
('Reenviar correos internos a mi correo personal para trabajar desde casa', FALSE, 'critico', 6),
('Abrir adjuntos ZIP sin problema si el correo viene de un conocido', FALSE, 'critico', 6);

-- Pregunta 7: Candado en el navegador
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Que el sitio web es 100% seguro y confiable',             FALSE, 'medio',   7),
('Que la conexión entre mi navegador y el sitio está cifrada (HTTPS)', TRUE, 'leve', 7),
('Que el sitio tiene licencia oficial del gobierno',        FALSE, 'leve',    7),
('Que el sitio no puede contener virus',                    FALSE, 'medio',   7);

-- Pregunta 8: Llamada de soporte técnico
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Doy acceso si suenan profesionales y conocen mi nombre',  FALSE, 'critico', 8),
('Cuelgo y contacto directamente al departamento de TI',    TRUE,  'leve',    8),
('Doy acceso solo por 5 minutos para que arreglen el problema', FALSE, 'critico', 8),
('Doy acceso pero los veo en pantalla para asegurarme',     FALSE, 'critico', 8);

-- Pregunta 9: Frecuencia cambio de contraseña
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Solo cuando me la pidan o crea que me la robaron',        FALSE, 'medio',   9),
('Cada 6 a 12 meses, o inmediatamente si sospecho compromiso', TRUE, 'leve',  9),
('Nunca, una contraseña fuerte no necesita cambiarse',      FALSE, 'critico', 9),
('Cada semana para máxima seguridad',                       FALSE, 'leve',    9);

-- Pregunta 10: Phishing
INSERT INTO respuestas (respuesta, es_correcta, nivel_compromiso, id_pregunta) VALUES
('Un tipo de virus que se instala al abrir archivos PDF',   FALSE, 'medio',   10),
('Un ataque que busca engañarte para entregar info confidencial', TRUE, 'leve', 10),
('Una técnica para acelerar la conexión a internet',        FALSE, 'leve',    10),
('Un programa para recuperar contraseñas olvidadas',        FALSE, 'leve',    10);

-- Verificar resultado
SELECT p.id_pregunta, LEFT(p.pregunta,45) AS pregunta,
       r.respuesta, r.es_correcta, r.nivel_compromiso
FROM preguntas p
JOIN respuestas r ON r.id_pregunta = p.id_pregunta
ORDER BY p.id_pregunta, r.id_respuesta;
