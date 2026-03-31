-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Servidor: localhost:3306
-- Tiempo de generación: 31-03-2026 a las 11:00:25
-- Versión del servidor: 10.11.16-MariaDB-cll-lve
-- Versión de PHP: 8.4.18

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `xygfyvca_disen101`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `asignaciones_facturas`
--

CREATE TABLE `asignaciones_facturas` (
  `id` int(11) NOT NULL,
  `factura_id` int(11) NOT NULL,
  `cobrador_id` int(11) NOT NULL,
  `fecha_asignacion` date NOT NULL,
  `estado` enum('activa','completada','reasignada') DEFAULT 'activa',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `asignaciones_facturas`
--

INSERT INTO `asignaciones_facturas` (`id`, `factura_id`, `cobrador_id`, `fecha_asignacion`, `estado`, `created_at`, `updated_at`) VALUES
(2253, 1827, 1, '2026-03-29', 'activa', '2026-03-29 05:37:48', '2026-03-29 05:37:48'),
(2254, 2547, 1, '2026-03-31', 'activa', '2026-03-29 06:54:08', '2026-03-29 06:54:08');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `beneficiarios`
--

CREATE TABLE `beneficiarios` (
  `id` int(11) NOT NULL,
  `contrato_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `apellidos` varchar(100) NOT NULL,
  `parentesco` varchar(50) NOT NULL,
  `porcentaje` decimal(5,2) NOT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `beneficiarios`
--

INSERT INTO `beneficiarios` (`id`, `contrato_id`, `nombre`, `apellidos`, `parentesco`, `porcentaje`, `fecha_nacimiento`, `created_at`, `updated_at`) VALUES
(118, 106, 'RAMON ANTIGUA', 'NUÑEZ MIRABAL', 'TITULAR', 100.00, '1939-08-15', '2025-01-03 15:39:05', '2025-01-03 15:39:05'),
(119, 107, 'RAFAEL', 'ORTEGA', 'TITULAR', 100.00, '1966-10-24', '2025-01-03 16:25:19', '2025-01-03 16:25:19'),
(120, 108, 'DASIEL MARIA', 'YNOA BAEZ', 'TITULAR', 100.00, '1947-07-29', '2025-01-03 17:27:10', '2025-01-03 17:27:10'),
(121, 109, 'WILTON', 'PEREZ', 'TITULAR', 100.00, '1990-01-01', '2025-01-03 18:18:19', '2025-01-03 18:18:19'),
(125, 112, 'ELISA MERCEDES', 'ABREU HICIANO', 'TITULAR', 100.00, '1957-06-14', '2025-01-08 00:51:50', '2025-01-08 00:51:50'),
(126, 113, 'BEATA', 'NUÑEZ (JUANA)', 'TITULAR', 100.00, '1965-03-01', '2025-01-08 01:17:31', '2025-01-08 01:17:31'),
(127, 114, 'GLORIALYS ALICIA', 'FIGUEROA UREÑA', 'TUTILAR', 100.00, '1981-04-18', '2025-01-08 01:41:08', '2025-01-08 01:41:08'),
(128, 115, ' FELICIA LUCIANO', 'ORTIZ DE INOA', 'TITULAR', 100.00, '1968-09-09', '2025-01-08 02:21:54', '2025-01-08 02:21:54'),
(129, 132, 'JUAN DE JESUS', 'RODRIGUEZ FERNANDEZ', 'TITULAR', 100.00, '1964-08-01', '2025-02-04 03:28:14', '2025-02-04 03:28:14'),
(130, 133, 'ADA ANTONIO', 'HEREDIA', 'TUTILAR', 100.00, '1974-08-05', '2025-02-09 23:06:21', '2025-02-09 23:06:21'),
(131, 135, 'KEITH SINCLAIR', 'MITCHAM', 'TUTILAR', 100.00, '1966-11-21', '2025-04-18 00:55:46', '2025-04-18 00:55:46'),
(132, 136, 'JOSE AMADO', 'PICHARDO ARIVOL', 'TITULAR', 100.00, '1900-01-01', '2025-05-11 13:26:09', '2025-05-11 13:26:09'),
(133, 28, 'NOAH SEBASTIAN  ', 'ROSA', 'NIETO', 6.00, '2019-01-03', '2025-11-23 00:22:58', '2025-11-23 00:22:58'),
(134, 2, 'GERARDINE ELIZABETH ', 'BATISTA', 'NADA', 3.00, '1988-04-22', '2025-11-23 00:55:18', '2025-11-23 00:55:18'),
(135, 1, 'BRIANNA ITZAE', 'LUNA SANTANA', 'NIETO', 6.00, '2202-04-17', '2025-11-30 17:47:41', '2025-11-30 17:47:41');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `beneficios_planes`
--

CREATE TABLE `beneficios_planes` (
  `id` int(11) NOT NULL,
  `plan_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `monto_cobertura` decimal(10,2) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `clientes`
--

CREATE TABLE `clientes` (
  `id` int(11) NOT NULL,
  `codigo` varchar(5) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `apellidos` varchar(100) NOT NULL,
  `cedula` varchar(13) NOT NULL,
  `telefono1` varchar(15) NOT NULL,
  `telefono2` varchar(15) DEFAULT NULL,
  `telefono3` varchar(15) DEFAULT NULL,
  `direccion` text NOT NULL,
  `email` varchar(100) NOT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  `fecha_registro` datetime NOT NULL,
  `estado` enum('activo','inactivo','suspendido') DEFAULT 'activo',
  `cobrador_id` int(11) NOT NULL,
  `vendedor_id` int(11) NOT NULL,
  `notas` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `clientes`
--

INSERT INTO `clientes` (`id`, `codigo`, `nombre`, `apellidos`, `cedula`, `telefono1`, `telefono2`, `telefono3`, `direccion`, `email`, `fecha_nacimiento`, `fecha_registro`, `estado`, `cobrador_id`, `vendedor_id`, `notas`, `created_at`, `updated_at`) VALUES
(1, '00001', 'LIDIA ALTAGRACIA', 'FERNANDEZ PEREZ', '048-0013726-9', '809-296-0188', '829-986-8356', '', '. CAMAÑO #19,PISO 2 BARRIO, PORSPERIDAD ', '-', '1940-05-29', '2008-02-06 00:00:00', 'activo', 1, 1, 'AL LADO DEL SALON CELINEE', '2024-12-06 17:00:00', '2025-11-30 17:40:05'),
(2, '00002', 'FRANCISCA ANTONIA', 'GARCIA MORALES', '048-0053350-0', '809-258-8819', '809-862-6161', '', 'CAMAÑO. NO 19 B/PROSPERIDAD BONAO ', '', '1969-06-15', '2008-02-04 00:00:00', 'activo', 1, 1, 'AL LADO DEL SALON SELINE', '2024-12-06 17:00:00', '2025-11-23 00:51:42'),
(3, '00003', 'ELETICIA', 'ROMERO SANTOS', '048-0033507-9', '829-396-0805', '849-3991052', '', 'C/EMBAJADA NO.22 BARRIO PROSPERIDAD BONAO', '', '1957-12-12', '2008-02-07 00:00:00', 'activo', 1, 1, 'EN EL COLMADITO', '2024-12-06 17:00:00', '2025-11-12 17:09:28');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cobradores`
--

CREATE TABLE `cobradores` (
  `id` int(11) NOT NULL,
  `codigo` varchar(3) NOT NULL,
  `nombre_completo` varchar(200) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `fecha_ingreso` date NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `usuario_id` int(11) DEFAULT NULL,
  `telefono` varchar(15) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `cobradores`
--

INSERT INTO `cobradores` (`id`, `codigo`, `nombre_completo`, `descripcion`, `fecha_ingreso`, `estado`, `usuario_id`, `telefono`, `email`, `created_at`, `updated_at`) VALUES
(1, '001', 'Rafael Green', '', '2024-11-19', 'activo', 3, NULL, NULL, '2024-11-19 22:41:01', '2026-03-29 10:01:46');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cobrador_facturas_autorizadas`
--

CREATE TABLE `cobrador_facturas_autorizadas` (
  `id` int(11) NOT NULL,
  `cobrador_id` int(11) NOT NULL,
  `factura_id` int(11) NOT NULL,
  `autorizado_por` int(11) NOT NULL,
  `fecha_autorizacion` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_expiracion` datetime DEFAULT NULL,
  `estado` enum('activa','usada','expirada') NOT NULL DEFAULT 'activa',
  `motivo` text DEFAULT NULL,
  `impresa` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_impresion` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cobrador_mensajes`
--

CREATE TABLE `cobrador_mensajes` (
  `id` int(11) NOT NULL,
  `cobrador_id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `asunto` varchar(150) NOT NULL,
  `mensaje` text NOT NULL,
  `prioridad` enum('normal','urgente','informativo') NOT NULL DEFAULT 'normal',
  `leido` tinyint(1) NOT NULL DEFAULT 0,
  `fecha_envio` datetime NOT NULL DEFAULT current_timestamp(),
  `fecha_leido` datetime DEFAULT NULL,
  `cliente_visita_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `cobrador_mensajes`
--

INSERT INTO `cobrador_mensajes` (`id`, `cobrador_id`, `usuario_id`, `asunto`, `mensaje`, `prioridad`, `leido`, `fecha_envio`, `fecha_leido`, `cliente_visita_id`, `created_at`) VALUES
(1, 1, 1, 'Bienvenido al Portal del Cobrador', 'Hola Rafael Green,\n\nTu portal de cobrador ha sido activado. Desde aquí podrás ver tus clientes asignados, revisar tus facturas pendientes, planear tu ruta diaria e imprimir comprobantes desde tu celular.\n\n¡Mucho éxito en tus cobros!', 'informativo', 1, '2026-03-29 06:01:46', '2026-03-30 22:19:31', NULL, '2026-03-29 10:01:46'),
(2, 1, 1, 'Visita', 'Visitar a la clienta Andrea, dice que estara en su casa a las 3 pm', 'normal', 1, '2026-03-30 22:43:51', '2026-03-30 22:44:19', 24, '2026-03-31 02:43:51'),
(3, 1, 1, 'Visita', 'Visitar a la clienta Andrea, dice que estara en su casa a las 3 pm', 'normal', 1, '2026-03-30 22:44:00', '2026-03-30 22:44:32', 24, '2026-03-31 02:44:00'),
(4, 1, 1, 'Hola', 'prueba', 'normal', 1, '2026-03-30 22:45:08', '2026-03-30 22:45:22', NULL, '2026-03-31 02:45:08'),
(5, 1, 1, 'Hola', 'prueba', 'normal', 1, '2026-03-30 22:45:42', '2026-03-30 22:47:07', NULL, '2026-03-31 02:45:42'),
(6, 1, 1, 'pasar por donde ana', 'Ir a cobrar al trabajo de Ana', 'urgente', 1, '2026-03-30 22:47:45', '2026-03-30 22:47:59', 129, '2026-03-31 02:47:45'),
(7, 1, 1, 'Prueba 1', 'Ir por donde Beatriz', 'urgente', 1, '2026-03-30 23:05:24', '2026-03-30 23:05:41', 22, '2026-03-31 03:05:24'),
(8, 1, 1, 'Hola', 'Hi', 'normal', 1, '2026-03-30 23:18:36', '2026-03-30 23:18:59', 52, '2026-03-31 03:18:36');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cobrador_rutas`
--

CREATE TABLE `cobrador_rutas` (
  `id` int(11) NOT NULL,
  `cobrador_id` int(11) NOT NULL,
  `cliente_id` int(11) NOT NULL,
  `orden` int(11) NOT NULL DEFAULT 0,
  `notas_ruta` varchar(255) DEFAULT NULL,
  `fecha` date NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cobrador_sesiones_log`
--

CREATE TABLE `cobrador_sesiones_log` (
  `id` int(11) NOT NULL,
  `cobrador_id` int(11) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `accion` enum('login','logout','login_fallido') NOT NULL DEFAULT 'login',
  `fecha_hora` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `cobrador_sesiones_log`
--

INSERT INTO `cobrador_sesiones_log` (`id`, `cobrador_id`, `ip_address`, `user_agent`, `accion`, `fecha_hora`) VALUES
(1, 1, '172.111.36.78', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1', 'login', '2026-03-30 23:17:39');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `configuracion_sistema`
--

CREATE TABLE `configuracion_sistema` (
  `id` int(11) NOT NULL,
  `nombre_empresa` varchar(100) NOT NULL,
  `rif` varchar(20) DEFAULT NULL,
  `direccion` text DEFAULT NULL,
  `telefono` varchar(15) DEFAULT NULL,
  `celular` varchar(15) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `logo_url` varchar(255) DEFAULT NULL,
  `moneda` varchar(10) DEFAULT 'USD',
  `dias_gracia_pago` int(11) DEFAULT 5,
  `formato_factura` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `configuracion_sistema`
--

INSERT INTO `configuracion_sistema` (`id`, `nombre_empresa`, `rif`, `direccion`, `telefono`, `celular`, `email`, `logo_url`, `moneda`, `dias_gracia_pago`, `formato_factura`, `created_at`, `updated_at`) VALUES
(1, 'MM Lab Studio', '133-30417-1', 'Av. Aniana Vargas #31 módulo 2, Plaza Aniana Vargas, Bonao, R.D.', '829-296-9899', '849-495-3232', 'contacto@sefure.com', 'uploads/logo_1734567095.png', 'USD', 5, '', '2024-11-14 02:26:35', '2026-03-28 05:24:26');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `contratos`
--

CREATE TABLE `contratos` (
  `id` int(11) NOT NULL,
  `numero_contrato` varchar(20) DEFAULT NULL,
  `cliente_id` int(11) NOT NULL,
  `plan_id` int(11) NOT NULL,
  `fecha_inicio` date NOT NULL,
  `fecha_fin` date DEFAULT NULL,
  `monto_mensual` decimal(10,2) NOT NULL,
  `monto_total` decimal(10,2) NOT NULL,
  `dia_cobro` int(11) NOT NULL,
  `estado` enum('activo','cancelado','suspendido') DEFAULT 'activo',
  `vendedor_id` int(11) DEFAULT NULL,
  `notas` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `contratos`
--

INSERT INTO `contratos` (`id`, `numero_contrato`, `cliente_id`, `plan_id`, `fecha_inicio`, `fecha_fin`, `monto_mensual`, `monto_total`, `dia_cobro`, `estado`, `vendedor_id`, `notas`, `created_at`, `updated_at`) VALUES
(1, '00001', 1, 1, '2008-02-06', '2026-03-14', 550.00, 550.00, 15, 'activo', 1, 'null', '2024-12-06 05:00:00', '2026-02-21 08:42:41'),
(2, '00002', 2, 1, '2008-02-04', '2026-01-31', 200.00, 200.00, 1, 'activo', 1, 'null', '2024-12-06 05:00:00', '2026-02-09 18:40:05'),
(3, '00003', 3, 1, '2008-02-07', '2026-03-06', 200.00, 200.00, 7, 'activo', 1, 'null', '2024-12-06 05:00:00', '2026-02-14 02:25:37');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `dependientes`
--

CREATE TABLE `dependientes` (
  `id` int(11) NOT NULL,
  `contrato_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `apellidos` varchar(100) NOT NULL,
  `relacion` varchar(50) NOT NULL,
  `fecha_nacimiento` date NOT NULL,
  `identificacion` varchar(20) NOT NULL,
  `telefono` varchar(15) DEFAULT NULL,
  `fecha_registro` date NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `plan_id` int(11) NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `dependientes`
--

INSERT INTO `dependientes` (`id`, `contrato_id`, `nombre`, `apellidos`, `relacion`, `fecha_nacimiento`, `identificacion`, `telefono`, `fecha_registro`, `email`, `plan_id`, `estado`, `created_at`, `updated_at`) VALUES
(1, 1, 'SANTIAGO', 'SANTANA FERNANDEZ', 'Otro', '1960-05-01', '048-0073333-1', '', '0000-00-00', '', 1, 'activo', '2024-12-07 03:23:00', '2024-12-07 03:23:00'),
(2, 1, 'THELMA', 'SANTANA FERNANDEZ', 'Otro', '1961-04-24', '001-1352567-9', NULL, '0000-00-00', NULL, 1, 'activo', '2024-12-03 03:23:00', '2025-12-28 00:08:31'),
(3, 1, 'TLICH MICHAEL', 'SANTANA FERNANDEZ', 'Otro', '1991-06-03', '048-0040958-5', '', '0000-00-00', '', 1, 'inactivo', '2024-12-03 03:23:00', '2024-12-03 03:23:00'),
(4, 1, 'KEYSI MICHEL', 'SANTANA FERNANDEZ', 'Otro', '1992-09-19', '048-0059285-1', '', '0000-00-00', '', 1, 'activo', '2024-12-03 03:23:00', '2025-09-03 03:09:53');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `descuentos`
--

CREATE TABLE `descuentos` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `tipo` enum('porcentaje','monto_fijo') NOT NULL,
  `valor` decimal(10,2) NOT NULL,
  `fecha_inicio` date NOT NULL,
  `fecha_fin` date DEFAULT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `descuentos`
--

INSERT INTO `descuentos` (`id`, `nombre`, `descripcion`, `tipo`, `valor`, `fecha_inicio`, `fecha_fin`, `estado`, `created_at`, `updated_at`) VALUES
(1, 'Descuento Pronto Pago', 'Descuento por pago anticipado', 'porcentaje', 10.00, '2024-01-01', '2024-12-31', 'activo', '2024-11-14 02:26:35', '2024-11-14 02:26:35'),
(2, 'Descuento Familiar', 'Descuento para planes familiares', 'porcentaje', 15.00, '2024-01-01', '2024-12-31', 'activo', '2024-11-14 02:26:35', '2024-11-14 02:26:35'),
(3, 'Descuento Especial', 'Descuento de temporada', 'monto_fijo', 25.00, '2024-03-01', '2024-03-31', 'activo', '2024-11-14 02:26:35', '2024-11-14 02:26:35'),
(4, 'Descuento Adulto Mayor', 'Descuento para mayores de 60', 'porcentaje', 20.00, '2024-01-01', '2024-12-31', 'activo', '2024-11-14 02:26:35', '2024-11-14 02:26:35'),
(5, 'Descuento Empleado', 'Descuento para empleados', 'porcentaje', 25.00, '2024-01-01', '2024-12-31', 'activo', '2024-11-14 02:26:35', '2024-11-14 02:26:35');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `descuentos_aplicados`
--

CREATE TABLE `descuentos_aplicados` (
  `id` int(11) NOT NULL,
  `contrato_id` int(11) NOT NULL,
  `descuento_id` int(11) NOT NULL,
  `fecha_aplicacion` date NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `facturas`
--

CREATE TABLE `facturas` (
  `id` int(11) NOT NULL,
  `numero_factura` varchar(7) NOT NULL,
  `cuota` int(11) NOT NULL,
  `mes_factura` varchar(7) NOT NULL,
  `contrato_id` int(11) NOT NULL,
  `fecha_emision` date NOT NULL,
  `fecha_vencimiento` date NOT NULL,
  `monto` decimal(10,2) NOT NULL,
  `monto_pendiente` decimal(10,2) DEFAULT 0.00,
  `estado` enum('pendiente','pagada','vencida','anulada','incompleta') DEFAULT 'pendiente',
  `notas` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `cantidad_dependientes` int(11) DEFAULT 0,
  `tiene_geriatrico` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `facturas`
--

INSERT INTO `facturas` (`id`, `numero_factura`, `cuota`, `mes_factura`, `contrato_id`, `fecha_emision`, `fecha_vencimiento`, `monto`, `monto_pendiente`, `estado`, `notas`, `created_at`, `updated_at`, `cantidad_dependientes`, `tiene_geriatrico`) VALUES
(1, '0000001', 1, '09/2024', 1, '2024-09-15', '2024-10-15', 450.00, 0.00, 'pagada', NULL, '2025-01-01 07:11:00', '2025-01-01 07:11:00', 4, 0),
(2, '0000002', 2, '10/2024', 1, '2024-10-15', '2024-11-15', 450.00, 0.00, 'pagada', NULL, '2025-01-01 07:11:00', '2025-01-01 07:11:00', 4, 0),
(3, '0000003', 3, '11/2024', 1, '2024-11-15', '2024-12-15', 450.00, 0.00, 'pagada', NULL, '2025-01-01 07:11:00', '2025-01-01 07:11:00', 4, 0);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `generacion_facturas_lock`
--

CREATE TABLE `generacion_facturas_lock` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `timestamp` datetime NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `generacion_facturas_lock`
--

INSERT INTO `generacion_facturas_lock` (`id`, `usuario_id`, `timestamp`, `estado`) VALUES
(28, 1, '2024-11-19 19:55:31', 'inactivo'),
(29, 1, '2024-11-19 22:32:57', 'inactivo'),
(30, 1, '2024-11-20 07:54:45', 'inactivo');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `generacion_lote_lock`
--

CREATE TABLE `generacion_lote_lock` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `timestamp` datetime NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `generacion_lote_lock`
--

INSERT INTO `generacion_lote_lock` (`id`, `usuario_id`, `timestamp`, `estado`) VALUES
(1, 1, '2025-01-08 19:50:46', 'inactivo'),
(2, 1, '2025-01-08 19:50:56', 'inactivo'),
(3, 1, '2025-01-08 20:08:38', 'inactivo');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `historial_cambios_plan`
--

CREATE TABLE `historial_cambios_plan` (
  `id` int(11) NOT NULL,
  `contrato_id` int(11) NOT NULL,
  `plan_anterior_id` int(11) NOT NULL,
  `plan_nuevo_id` int(11) NOT NULL,
  `fecha_cambio` datetime NOT NULL,
  `motivo` text DEFAULT NULL,
  `usuario_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `historial_cambios_plan_dependientes`
--

CREATE TABLE `historial_cambios_plan_dependientes` (
  `id` int(11) NOT NULL,
  `dependiente_id` int(11) NOT NULL,
  `plan_anterior_id` int(11) NOT NULL,
  `plan_nuevo_id` int(11) NOT NULL,
  `fecha_cambio` datetime NOT NULL,
  `motivo` text DEFAULT NULL,
  `usuario_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `historial_reasignaciones`
--

CREATE TABLE `historial_reasignaciones` (
  `id` int(11) NOT NULL,
  `asignacion_id` int(11) NOT NULL,
  `cobrador_anterior_id` int(11) NOT NULL,
  `fecha_anterior` date NOT NULL,
  `cobrador_nuevo_id` int(11) NOT NULL,
  `fecha_nueva` date NOT NULL,
  `motivo` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `logs_sistema`
--

CREATE TABLE `logs_sistema` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `accion` varchar(100) NOT NULL,
  `tabla_afectada` varchar(50) DEFAULT NULL,
  `registro_id` int(11) DEFAULT NULL,
  `detalles` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `logs_sistema`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `pagos`
--

CREATE TABLE `pagos` (
  `id` int(11) NOT NULL,
  `factura_id` int(11) NOT NULL,
  `monto` decimal(10,2) NOT NULL,
  `fecha_pago` datetime NOT NULL,
  `metodo_pago` enum('efectivo','transferencia','cheque') NOT NULL,
  `referencia_pago` varchar(50) DEFAULT NULL,
  `cobrador_id` int(11) DEFAULT NULL,
  `estado` enum('procesado','anulado') DEFAULT 'procesado',
  `notas` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `tipo_pago` enum('total','abono') DEFAULT 'total'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `pagos`
--

INSERT INTO `pagos` (`id`, `factura_id`, `monto`, `fecha_pago`, `metodo_pago`, `referencia_pago`, `cobrador_id`, `estado`, `notas`, `created_at`, `tipo_pago`) VALUES
(1, 1, 450.00, '2024-09-15 00:00:00', 'efectivo', NULL, 1, 'procesado', NULL, '2024-09-15 04:00:00', 'total'),
(2, 2, 450.00, '2024-10-15 00:00:00', 'efectivo', NULL, 1, 'procesado', NULL, '2024-10-15 04:00:00', 'total'),
(3, 3, 450.00, '2024-11-15 00:00:00', 'efectivo', NULL, 1, 'procesado', NULL, '2024-11-15 05:00:00', 'total');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `planes`
--

CREATE TABLE `planes` (
  `id` int(11) NOT NULL,
  `codigo` varchar(20) DEFAULT NULL,
  `nombre` varchar(100) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `precio_base` decimal(10,2) NOT NULL,
  `cobertura_maxima` decimal(10,2) DEFAULT NULL,
  `edad_minima` int(11) DEFAULT NULL,
  `edad_maxima` int(11) DEFAULT NULL,
  `periodo_carencia` int(11) DEFAULT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `planes`
--

INSERT INTO `planes` (`id`, `codigo`, `nombre`, `descripcion`, `precio_base`, `cobertura_maxima`, `edad_minima`, `edad_maxima`, `periodo_carencia`, `estado`, `created_at`, `updated_at`) VALUES
(1, 'PLAN001', 'F', 'Plan de cobertura básica', 0.00, 25000.00, 1, 65, 180, 'activo', '2024-11-14 02:26:35', '2025-01-04 06:34:17'),
(2, 'PLAN002', 'Familiar', 'Plan de cobertura familiar', 0.00, 35000.00, 1, 65, 180, 'activo', '2024-11-14 02:26:35', '2025-01-04 06:34:58'),
(3, 'PLAN003', 'Premium', 'Plan de cobertura premium', 0.00, 50000.00, 1, 65, 180, 'activo', '2024-11-14 02:26:35', '2025-01-04 06:35:04'),
(4, 'PLAN004', 'Especial', 'Plan de cobertura Especial', 0.00, 43000.00, 1, 65, 180, 'activo', '2024-11-14 02:26:35', '2025-01-04 06:35:09'),
(5, 'PLAN005', 'Geriátrico', 'Plan especial para adultos mayores', 0.00, 25000.00, 65, 75, 180, 'activo', '2024-11-14 02:26:35', '2025-01-04 06:34:49');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `referencias_clientes`
--

CREATE TABLE `referencias_clientes` (
  `id` int(11) NOT NULL,
  `cliente_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `relacion` varchar(50) NOT NULL,
  `telefono` varchar(15) NOT NULL,
  `direccion` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `reportes_auditoria`
--

CREATE TABLE `reportes_auditoria` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `accion` varchar(50) NOT NULL,
  `detalles` text NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `fecha_hora` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `reportes_auditoria`
--

INSERT INTO `reportes_auditoria` (`id`, `usuario_id`, `accion`, `detalles`, `ip_address`, `fecha_hora`) VALUES
(1, 5, 'anulacion_pago', '{\"pago_id\":1257,\"factura_id\":1545,\"monto\":\"50.00\",\"estado_anterior\":\"pagada\",\"nuevo_estado\":\"incompleta\"}', '190.8.34.162', '2025-07-09 18:05:48'),
(2, 1, 'anulacion_pago', '{\"pago_id\":2187,\"factura_id\":2547,\"monto\":\"1000.00\",\"estado_anterior\":\"incompleta\",\"nuevo_estado\":\"pendiente\"}', '66.98.16.139', '2026-03-29 02:58:11');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `reportes_historial`
--

CREATE TABLE `reportes_historial` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `tipo_reporte` varchar(50) NOT NULL,
  `parametros` text NOT NULL,
  `fecha_generacion` datetime NOT NULL,
  `tiempo_generacion` decimal(10,2) DEFAULT NULL,
  `registros_procesados` int(11) DEFAULT NULL,
  `estado` enum('completado','error','en_proceso') DEFAULT 'en_proceso',
  `mensaje_error` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `reportes_historial`
--

INSERT INTO `reportes_historial` (`id`, `usuario_id`, `tipo_reporte`, `parametros`, `fecha_generacion`, `tiempo_generacion`, `registros_procesados`, `estado`, `mensaje_error`, `created_at`) VALUES
(1, 1, 'General', '{\"tipo\":\"General\",\"tipoReporte\":\"clientes_contratos\",\"fechaDesde\":\"2025-01-01\",\"fechaHasta\":\"2025-01-26\",\"formato\":\"pdf\"}', '2025-01-26 11:21:00', NULL, NULL, 'en_proceso', NULL, '2025-01-26 16:21:00'),
(2, 1, 'General', '{\"tipo\":\"General\",\"tipoReporte\":\"clientes_contratos\",\"fechaDesde\":\"2025-01-01\",\"fechaHasta\":\"2025-01-26\",\"formato\":\"excel\"}', '2025-01-26 11:21:16', NULL, NULL, 'en_proceso', NULL, '2025-01-26 16:21:16'),
(3, 1, 'General', '{\"tipo\":\"General\",\"tipoReporte\":\"clientes_contratos\",\"fechaDesde\":\"2025-03-01\",\"fechaHasta\":\"2025-03-16\",\"formato\":\"pdf\"}', '2025-03-16 17:51:36', NULL, NULL, 'en_proceso', NULL, '2025-03-16 21:51:36'),
(4, 1, 'Facturacion', '{\"tipo\":\"Facturacion\",\"tipoReporte\":\"\",\"fechaDesde\":\"2025-03-01\",\"fechaHasta\":\"2025-03-16\",\"estadoFactura\":\"\",\"planId\":\"\",\"formato\":\"excel\"}', '2025-03-16 18:43:53', NULL, NULL, 'en_proceso', NULL, '2025-03-16 22:43:53'),
(5, 1, 'General', '{\"tipo\":\"General\",\"tipoReporte\":\"clientes_contratos\",\"fechaDesde\":\"2025-03-01\",\"fechaHasta\":\"2025-03-16\",\"formato\":\"excel\"}', '2025-03-16 18:44:24', NULL, NULL, 'en_proceso', NULL, '2025-03-16 22:44:24'),
(6, 1, 'General', '{\"tipo\":\"General\",\"tipoReporte\":\"clientes_contratos\",\"fechaDesde\":\"2025-03-01\",\"fechaHasta\":\"2025-03-16\",\"formato\":\"xlsx\"}', '2025-03-16 18:45:28', NULL, NULL, 'en_proceso', NULL, '2025-03-16 22:45:28');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `reportes_notas`
--

CREATE TABLE `reportes_notas` (
  `id` int(11) NOT NULL,
  `reporte_id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `nota` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios`
--

CREATE TABLE `usuarios` (
  `id` int(11) NOT NULL,
  `usuario` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `rol` enum('admin','vendedor','cobrador','supervisor') NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `ultimo_acceso` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `usuarios`
--

INSERT INTO `usuarios` (`id`, `usuario`, `password`, `nombre`, `email`, `rol`, `estado`, `ultimo_acceso`, `created_at`, `updated_at`) VALUES
(1, 'orthiis', '$2y$10$MtBzI1F931yaEFKAZddVMui.KML5Nw2VBGgXrBj9bZ0bbl85bdoJa', 'Rafael Green', 'orthiis1982@gmail.com', 'admin', 'activo', '2026-03-28 12:40:58', '2024-11-13 03:22:51', '2026-03-28 16:40:58'),
(2, 'vendedor1', '$2y$10$MtBzI1F931yaEFKAZddVMui.KML5Nw2VBGgXrBj9bZ0bbl85bdoJa', 'Vendedor', 'vendedor@sefure.com', 'vendedor', 'activo', '2024-11-14 09:13:02', '2024-11-14 02:26:35', '2025-01-11 19:20:29'),
(3, 'cobrador1', '$2y$10$MtBzI1F931yaEFKAZddVMui.KML5Nw2VBGgXrBj9bZ0bbl85bdoJa', 'Rafael Green', 'rafaelgreen@sefure.com', 'cobrador', 'activo', '2026-03-30 23:17:39', '2024-11-14 02:26:35', '2026-03-31 03:17:39'),
(4, 'supervisor1', '$2y$10$MW0uEfQLncxClxW8VelrNOOVD3UChTTU2Zbajaivlgrb2BwWxJ4Gq', 'Supervisor', 'supervisor@sefure.com', 'supervisor', 'activo', '2025-10-31 21:39:03', '2024-11-14 02:26:35', '2025-11-01 01:39:03'),
(5, 'anairis', '$2y$10$MtBzI1F931yaEFKAZddVMui.KML5Nw2VBGgXrBj9bZ0bbl85bdoJa', 'Ana Iris Abad', 'anairis.abad@segurosbonao.com', 'admin', 'activo', '2026-02-02 13:00:07', '2024-11-14 02:26:35', '2026-02-02 18:00:07'),
(6, 'orthiis2', '$2y$10$ttVrrOOpJast.F059HP/p.rtsHNsmno6qyEwozv./sumjZWINyXsS', 'Miguel Angel 2', 'miguel@angel.com', 'admin', 'activo', '2024-11-18 14:21:59', '2024-11-18 19:21:33', '2025-03-16 14:35:44');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `vendedores`
--

CREATE TABLE `vendedores` (
  `id` int(11) NOT NULL,
  `codigo` varchar(3) NOT NULL,
  `nombre_completo` varchar(200) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `fecha_ingreso` date NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_unicode_ci;

--
-- Volcado de datos para la tabla `vendedores`
--

INSERT INTO `vendedores` (`id`, `codigo`, `nombre_completo`, `descripcion`, `fecha_ingreso`, `estado`, `created_at`, `updated_at`) VALUES
(1, '001', 'Plafucom', '', '2024-11-19', 'activo', '2024-11-19 22:40:20', '2025-01-01 23:03:43'),
(2, '002', 'Rafael Green', 'Rafael Green', '2025-02-07', 'activo', '2025-02-08 01:56:45', '2025-02-08 01:56:45'),
(3, '003', 'Ana Iris', 'Ana Iris', '2025-02-12', 'activo', '2025-02-12 12:32:40', '2025-02-12 12:32:40');

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `asignaciones_facturas`
--
ALTER TABLE `asignaciones_facturas`
  ADD PRIMARY KEY (`id`),
  ADD KEY `factura_id` (`factura_id`),
  ADD KEY `cobrador_id` (`cobrador_id`);

--
-- Indices de la tabla `beneficiarios`
--
ALTER TABLE `beneficiarios`
  ADD PRIMARY KEY (`id`),
  ADD KEY `contrato_id` (`contrato_id`);

--
-- Indices de la tabla `beneficios_planes`
--
ALTER TABLE `beneficios_planes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `plan_id` (`plan_id`);

--
-- Indices de la tabla `clientes`
--
ALTER TABLE `clientes`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `codigo` (`codigo`),
  ADD UNIQUE KEY `cedula` (`cedula`),
  ADD KEY `cobrador_id` (`cobrador_id`),
  ADD KEY `fk_cliente_vendedor` (`vendedor_id`);

--
-- Indices de la tabla `cobradores`
--
ALTER TABLE `cobradores`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `codigo` (`codigo`),
  ADD KEY `fk_cobrador_usuario` (`usuario_id`);

--
-- Indices de la tabla `cobrador_facturas_autorizadas`
--
ALTER TABLE `cobrador_facturas_autorizadas`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_cobrador_factura` (`cobrador_id`,`factura_id`),
  ADD KEY `idx_cobrador_estado` (`cobrador_id`,`estado`),
  ADD KEY `idx_factura_id` (`factura_id`),
  ADD KEY `idx_autorizado_por` (`autorizado_por`);

--
-- Indices de la tabla `cobrador_mensajes`
--
ALTER TABLE `cobrador_mensajes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_cobrador_leido` (`cobrador_id`,`leido`),
  ADD KEY `idx_usuario_id` (`usuario_id`),
  ADD KEY `idx_fecha_envio` (`fecha_envio`);

--
-- Indices de la tabla `cobrador_rutas`
--
ALTER TABLE `cobrador_rutas`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_cobrador_cliente_fecha` (`cobrador_id`,`cliente_id`,`fecha`),
  ADD KEY `idx_cobrador_fecha` (`cobrador_id`,`fecha`),
  ADD KEY `fk_ruta_cliente` (`cliente_id`);

--
-- Indices de la tabla `cobrador_sesiones_log`
--
ALTER TABLE `cobrador_sesiones_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_cobrador_fecha` (`cobrador_id`,`fecha_hora`);

--
-- Indices de la tabla `configuracion_sistema`
--
ALTER TABLE `configuracion_sistema`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `contratos`
--
ALTER TABLE `contratos`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `numero_contrato` (`numero_contrato`),
  ADD KEY `cliente_id` (`cliente_id`),
  ADD KEY `plan_id` (`plan_id`),
  ADD KEY `vendedor_id` (`vendedor_id`);

--
-- Indices de la tabla `dependientes`
--
ALTER TABLE `dependientes`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `identificacion` (`identificacion`),
  ADD KEY `plan_id` (`plan_id`),
  ADD KEY `contrato_id` (`contrato_id`);

--
-- Indices de la tabla `descuentos`
--
ALTER TABLE `descuentos`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `descuentos_aplicados`
--
ALTER TABLE `descuentos_aplicados`
  ADD PRIMARY KEY (`id`),
  ADD KEY `contrato_id` (`contrato_id`),
  ADD KEY `descuento_id` (`descuento_id`);

--
-- Indices de la tabla `facturas`
--
ALTER TABLE `facturas`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `idx_contrato_mes` (`contrato_id`,`mes_factura`),
  ADD UNIQUE KEY `idx_contrato_cuota` (`contrato_id`,`cuota`),
  ADD UNIQUE KEY `numero_factura` (`numero_factura`),
  ADD UNIQUE KEY `numero_factura_unique` (`numero_factura`),
  ADD KEY `contrato_id` (`contrato_id`),
  ADD KEY `idx_estado_facturas` (`estado`),
  ADD KEY `idx_fecha_emision` (`fecha_emision`),
  ADD KEY `idx_factura_estado` (`estado`),
  ADD KEY `idx_contrato_estado_id` (`contrato_id`,`estado`,`id`);

--
-- Indices de la tabla `generacion_facturas_lock`
--
ALTER TABLE `generacion_facturas_lock`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `generacion_lote_lock`
--
ALTER TABLE `generacion_lote_lock`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `historial_cambios_plan`
--
ALTER TABLE `historial_cambios_plan`
  ADD PRIMARY KEY (`id`),
  ADD KEY `contrato_id` (`contrato_id`),
  ADD KEY `plan_anterior_id` (`plan_anterior_id`),
  ADD KEY `plan_nuevo_id` (`plan_nuevo_id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `historial_cambios_plan_dependientes`
--
ALTER TABLE `historial_cambios_plan_dependientes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `dependiente_id` (`dependiente_id`),
  ADD KEY `plan_anterior_id` (`plan_anterior_id`),
  ADD KEY `plan_nuevo_id` (`plan_nuevo_id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `historial_reasignaciones`
--
ALTER TABLE `historial_reasignaciones`
  ADD PRIMARY KEY (`id`),
  ADD KEY `asignacion_id` (`asignacion_id`);

--
-- Indices de la tabla `logs_sistema`
--
ALTER TABLE `logs_sistema`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `pagos`
--
ALTER TABLE `pagos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `factura_id` (`factura_id`),
  ADD KEY `cobrador_id` (`cobrador_id`),
  ADD KEY `idx_pago_tipo` (`tipo_pago`),
  ADD KEY `idx_factura_estado_pago` (`factura_id`,`estado`);

--
-- Indices de la tabla `planes`
--
ALTER TABLE `planes`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `codigo` (`codigo`);

--
-- Indices de la tabla `referencias_clientes`
--
ALTER TABLE `referencias_clientes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `cliente_id` (`cliente_id`);

--
-- Indices de la tabla `reportes_auditoria`
--
ALTER TABLE `reportes_auditoria`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `reportes_historial`
--
ALTER TABLE `reportes_historial`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `reportes_notas`
--
ALTER TABLE `reportes_notas`
  ADD PRIMARY KEY (`id`),
  ADD KEY `reporte_id` (`reporte_id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `usuario` (`usuario`);

--
-- Indices de la tabla `vendedores`
--
ALTER TABLE `vendedores`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `codigo` (`codigo`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `asignaciones_facturas`
--
ALTER TABLE `asignaciones_facturas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2255;

--
-- AUTO_INCREMENT de la tabla `beneficiarios`
--
ALTER TABLE `beneficiarios`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=136;

--
-- AUTO_INCREMENT de la tabla `beneficios_planes`
--
ALTER TABLE `beneficios_planes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `clientes`
--
ALTER TABLE `clientes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=136;

--
-- AUTO_INCREMENT de la tabla `cobradores`
--
ALTER TABLE `cobradores`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `cobrador_facturas_autorizadas`
--
ALTER TABLE `cobrador_facturas_autorizadas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `cobrador_mensajes`
--
ALTER TABLE `cobrador_mensajes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT de la tabla `cobrador_rutas`
--
ALTER TABLE `cobrador_rutas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `cobrador_sesiones_log`
--
ALTER TABLE `cobrador_sesiones_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `configuracion_sistema`
--
ALTER TABLE `configuracion_sistema`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `contratos`
--
ALTER TABLE `contratos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=138;

--
-- AUTO_INCREMENT de la tabla `dependientes`
--
ALTER TABLE `dependientes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=602;

--
-- AUTO_INCREMENT de la tabla `descuentos`
--
ALTER TABLE `descuentos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `descuentos_aplicados`
--
ALTER TABLE `descuentos_aplicados`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `facturas`
--
ALTER TABLE `facturas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2560;

--
-- AUTO_INCREMENT de la tabla `generacion_facturas_lock`
--
ALTER TABLE `generacion_facturas_lock`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=491;

--
-- AUTO_INCREMENT de la tabla `generacion_lote_lock`
--
ALTER TABLE `generacion_lote_lock`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=233;

--
-- AUTO_INCREMENT de la tabla `historial_cambios_plan`
--
ALTER TABLE `historial_cambios_plan`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT de la tabla `historial_cambios_plan_dependientes`
--
ALTER TABLE `historial_cambios_plan_dependientes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `historial_reasignaciones`
--
ALTER TABLE `historial_reasignaciones`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=469;

--
-- AUTO_INCREMENT de la tabla `logs_sistema`
--
ALTER TABLE `logs_sistema`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=183;

--
-- AUTO_INCREMENT de la tabla `pagos`
--
ALTER TABLE `pagos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2189;

--
-- AUTO_INCREMENT de la tabla `planes`
--
ALTER TABLE `planes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `referencias_clientes`
--
ALTER TABLE `referencias_clientes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `reportes_auditoria`
--
ALTER TABLE `reportes_auditoria`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT de la tabla `reportes_historial`
--
ALTER TABLE `reportes_historial`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT de la tabla `reportes_notas`
--
ALTER TABLE `reportes_notas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT de la tabla `vendedores`
--
ALTER TABLE `vendedores`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `asignaciones_facturas`
--
ALTER TABLE `asignaciones_facturas`
  ADD CONSTRAINT `fk_asignacion_cobrador` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`),
  ADD CONSTRAINT `fk_asignacion_factura` FOREIGN KEY (`factura_id`) REFERENCES `facturas` (`id`);

--
-- Filtros para la tabla `beneficiarios`
--
ALTER TABLE `beneficiarios`
  ADD CONSTRAINT `beneficiarios_ibfk_1` FOREIGN KEY (`contrato_id`) REFERENCES `contratos` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `beneficios_planes`
--
ALTER TABLE `beneficios_planes`
  ADD CONSTRAINT `beneficios_planes_ibfk_1` FOREIGN KEY (`plan_id`) REFERENCES `planes` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `clientes`
--
ALTER TABLE `clientes`
  ADD CONSTRAINT `fk_cliente_cobrador` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`),
  ADD CONSTRAINT `fk_cliente_vendedor` FOREIGN KEY (`vendedor_id`) REFERENCES `vendedores` (`id`);

--
-- Filtros para la tabla `cobradores`
--
ALTER TABLE `cobradores`
  ADD CONSTRAINT `fk_cobrador_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Filtros para la tabla `cobrador_facturas_autorizadas`
--
ALTER TABLE `cobrador_facturas_autorizadas`
  ADD CONSTRAINT `fk_aut_cobrador` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_aut_factura` FOREIGN KEY (`factura_id`) REFERENCES `facturas` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_aut_usuario` FOREIGN KEY (`autorizado_por`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `cobrador_mensajes`
--
ALTER TABLE `cobrador_mensajes`
  ADD CONSTRAINT `fk_msg_cobrador` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_msg_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `cobrador_rutas`
--
ALTER TABLE `cobrador_rutas`
  ADD CONSTRAINT `fk_ruta_cliente` FOREIGN KEY (`cliente_id`) REFERENCES `clientes` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ruta_cobrador` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `cobrador_sesiones_log`
--
ALTER TABLE `cobrador_sesiones_log`
  ADD CONSTRAINT `fk_sesion_cobrador` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `contratos`
--
ALTER TABLE `contratos`
  ADD CONSTRAINT `contratos_ibfk_1` FOREIGN KEY (`cliente_id`) REFERENCES `clientes` (`id`),
  ADD CONSTRAINT `contratos_ibfk_2` FOREIGN KEY (`plan_id`) REFERENCES `planes` (`id`),
  ADD CONSTRAINT `contratos_ibfk_3` FOREIGN KEY (`vendedor_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `dependientes`
--
ALTER TABLE `dependientes`
  ADD CONSTRAINT `dependientes_ibfk_1` FOREIGN KEY (`contrato_id`) REFERENCES `contratos` (`id`),
  ADD CONSTRAINT `dependientes_ibfk_2` FOREIGN KEY (`plan_id`) REFERENCES `planes` (`id`);

--
-- Filtros para la tabla `descuentos_aplicados`
--
ALTER TABLE `descuentos_aplicados`
  ADD CONSTRAINT `descuentos_aplicados_ibfk_1` FOREIGN KEY (`contrato_id`) REFERENCES `contratos` (`id`),
  ADD CONSTRAINT `descuentos_aplicados_ibfk_2` FOREIGN KEY (`descuento_id`) REFERENCES `descuentos` (`id`);

--
-- Filtros para la tabla `facturas`
--
ALTER TABLE `facturas`
  ADD CONSTRAINT `facturas_ibfk_1` FOREIGN KEY (`contrato_id`) REFERENCES `contratos` (`id`);

--
-- Filtros para la tabla `generacion_facturas_lock`
--
ALTER TABLE `generacion_facturas_lock`
  ADD CONSTRAINT `generacion_facturas_lock_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `historial_cambios_plan`
--
ALTER TABLE `historial_cambios_plan`
  ADD CONSTRAINT `historial_cambios_plan_ibfk_1` FOREIGN KEY (`contrato_id`) REFERENCES `contratos` (`id`),
  ADD CONSTRAINT `historial_cambios_plan_ibfk_2` FOREIGN KEY (`plan_anterior_id`) REFERENCES `planes` (`id`),
  ADD CONSTRAINT `historial_cambios_plan_ibfk_3` FOREIGN KEY (`plan_nuevo_id`) REFERENCES `planes` (`id`),
  ADD CONSTRAINT `historial_cambios_plan_ibfk_4` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `historial_cambios_plan_dependientes`
--
ALTER TABLE `historial_cambios_plan_dependientes`
  ADD CONSTRAINT `hist_cambios_dep_ibfk_1` FOREIGN KEY (`dependiente_id`) REFERENCES `dependientes` (`id`),
  ADD CONSTRAINT `hist_cambios_dep_ibfk_2` FOREIGN KEY (`plan_anterior_id`) REFERENCES `planes` (`id`),
  ADD CONSTRAINT `hist_cambios_dep_ibfk_3` FOREIGN KEY (`plan_nuevo_id`) REFERENCES `planes` (`id`),
  ADD CONSTRAINT `hist_cambios_dep_ibfk_4` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `historial_reasignaciones`
--
ALTER TABLE `historial_reasignaciones`
  ADD CONSTRAINT `fk_historial_asignacion` FOREIGN KEY (`asignacion_id`) REFERENCES `asignaciones_facturas` (`id`);

--
-- Filtros para la tabla `logs_sistema`
--
ALTER TABLE `logs_sistema`
  ADD CONSTRAINT `logs_sistema_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `pagos`
--
ALTER TABLE `pagos`
  ADD CONSTRAINT `pagos_ibfk_1` FOREIGN KEY (`factura_id`) REFERENCES `facturas` (`id`),
  ADD CONSTRAINT `pagos_ibfk_2` FOREIGN KEY (`cobrador_id`) REFERENCES `cobradores` (`id`);

--
-- Filtros para la tabla `referencias_clientes`
--
ALTER TABLE `referencias_clientes`
  ADD CONSTRAINT `referencias_clientes_ibfk_1` FOREIGN KEY (`cliente_id`) REFERENCES `clientes` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `reportes_auditoria`
--
ALTER TABLE `reportes_auditoria`
  ADD CONSTRAINT `reportes_auditoria_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `reportes_historial`
--
ALTER TABLE `reportes_historial`
  ADD CONSTRAINT `reportes_historial_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `reportes_notas`
--
ALTER TABLE `reportes_notas`
  ADD CONSTRAINT `reportes_notas_ibfk_1` FOREIGN KEY (`reporte_id`) REFERENCES `reportes_historial` (`id`),
  ADD CONSTRAINT `reportes_notas_ibfk_2` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`);

DELIMITER $$
--
-- Eventos
--
CREATE EVENT `evt_actualizar_vencidas` ON SCHEDULE EVERY 1 DAY STARTS '2026-03-28 00:00:00' ON COMPLETION NOT PRESERVE ENABLE DO CALL sp_actualizar_facturas_vencidas()$$

DELIMITER ;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
