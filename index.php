<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ORTHIIS — Servicios Funerarios | Seguros de Vida</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <style>
        /* ============================================================
           VARIABLES
        ============================================================ */
        :root {
            --primary:       #0a1f44;
            --primary-light: #142d5e;
            --secondary:     #1a3a6b;
            --accent:        #2563eb;
            --accent-light:  #3b82f6;
            --accent-glow:   rgba(37,99,235,0.15);
            --orange:        #f97316;
            --orange-light:  #fb923c;
            --green:         #10b981;
            --cyan:          #06b6d4;
            --red:           #ef4444;
            --purple:        #8b5cf6;
            --gold:          #f59e0b;
            --bg-light:      #f8fafc;
            --bg-gray:       #f1f5f9;
            --white:         #ffffff;
            --text-dark:     #0f172a;
            --text-body:     #475569;
            --text-muted:    #94a3b8;
            --border:        #e2e8f0;
            --shadow-sm:     0 1px 3px rgba(0,0,0,.06);
            --shadow-md:     0 4px 16px rgba(0,0,0,.08);
            --shadow-lg:     0 12px 40px rgba(0,0,0,.12);
            --shadow-xl:     0 20px 60px rgba(0,0,0,.15);
            --radius:        12px;
            --radius-lg:     16px;
            --radius-xl:     20px;
            --transition:    all .3s cubic-bezier(.4,0,.2,1);
        }

        /* ============================================================
           RESET
        ============================================================ */
        *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
        html { scroll-behavior: smooth; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            color: var(--text-body);
            background: var(--white);
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }
        a { text-decoration: none; color: inherit; }
        ul { list-style: none; }
        img { max-width:100%; height:auto; display:block; }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        /* ============================================================
           TOPBAR
        ============================================================ */
        .topbar {
            background: var(--primary);
            color: rgba(255,255,255,.8);
            font-size: 13px;
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,.08);
        }
        .topbar .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .topbar-left {
            display: flex;
            align-items: center;
            gap: 24px;
        }
        .topbar-left span {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .topbar-left i { color: var(--accent-light); font-size: 12px; }
        .topbar-right {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .topbar-right a {
            color: rgba(255,255,255,.7);
            font-size: 14px;
            transition: var(--transition);
        }
        .topbar-right a:hover { color: var(--accent-light); }

        /* ============================================================
           NAVBAR
        ============================================================ */
        .navbar {
            background: var(--white);
            padding: 0;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: var(--shadow-sm);
            transition: var(--transition);
        }
        .navbar.scrolled { box-shadow: var(--shadow-md); }
        .navbar .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 75px;
        }
        .nav-logo {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nav-logo-icon {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, var(--accent), var(--primary));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-size: 20px;
        }
        .nav-logo-text {
            font-size: 22px;
            font-weight: 800;
            color: var(--primary);
            letter-spacing: -0.5px;
        }
        .nav-logo-text span { color: var(--accent); }
        .nav-links {
            display: flex;
            align-items: center;
            gap: 32px;
        }
        .nav-links a {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-dark);
            transition: var(--transition);
            position: relative;
            padding: 8px 0;
        }
        .nav-links a:hover,
        .nav-links a.active { color: var(--accent); }
        .nav-links a::after {
            content: '';
            position: absolute;
            bottom: 0; left: 0;
            width: 0; height: 2px;
            background: var(--accent);
            transition: var(--transition);
        }
        .nav-links a:hover::after,
        .nav-links a.active::after { width: 100%; }
        .nav-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .nav-phone {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 700;
            color: var(--accent);
        }
        .nav-phone i {
            width: 36px; height: 36px;
            background: var(--accent-glow);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
        }
        .nav-cta {
            background: var(--accent);
            color: var(--white);
            padding: 10px 22px;
            border-radius: var(--radius);
            font-size: 13px;
            font-weight: 700;
            transition: var(--transition);
            border: none;
            cursor: pointer;
        }
        .nav-cta:hover {
            background: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(37,99,235,.3);
        }

        /* Mobile menu */
        .mobile-toggle {
            display: none;
            background: none;
            border: none;
            font-size: 22px;
            color: var(--text-dark);
            cursor: pointer;
        }

        /* ============================================================
           HERO
        ============================================================ */
        .hero {
            position: relative;
            min-height: 600px;
            display: flex;
            align-items: center;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 50%, var(--accent) 100%);
            overflow: hidden;
            padding: 80px 0;
        }
        .hero::before {
            content: '';
            position: absolute;
            inset: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        }
        .hero .container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 60px;
            position: relative;
            z-index: 2;
        }
        .hero-content {
            flex: 1;
            max-width: 560px;
        }
        .hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(255,255,255,.12);
            border: 1px solid rgba(255,255,255,.2);
            color: var(--white);
            padding: 6px 16px;
            border-radius: 30px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        .hero-badge i { color: var(--orange); }
        .hero h1 {
            font-family: 'Playfair Display', serif;
            font-size: 52px;
            font-weight: 800;
            color: var(--white);
            line-height: 1.15;
            margin-bottom: 20px;
        }
        .hero h1 span { color: var(--orange); display: block; }
        .hero-desc {
            font-size: 16px;
            color: rgba(255,255,255,.8);
            line-height: 1.7;
            margin-bottom: 32px;
        }
        .hero-buttons {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }
        .btn-hero-primary {
            background: var(--orange);
            color: var(--white);
            padding: 14px 32px;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 700;
            border: none;
            cursor: pointer;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn-hero-primary:hover {
            background: var(--orange-light);
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(249,115,22,.35);
        }
        .btn-hero-outline {
            background: transparent;
            color: var(--white);
            padding: 14px 32px;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 700;
            border: 2px solid rgba(255,255,255,.3);
            cursor: pointer;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn-hero-outline:hover {
            background: rgba(255,255,255,.1);
            border-color: rgba(255,255,255,.6);
        }
        .hero-image {
            flex: 1;
            max-width: 500px;
            position: relative;
        }
        .hero-image img {
            border-radius: var(--radius-xl);
            box-shadow: 0 20px 60px rgba(0,0,0,.3);
        }
        .hero-float-card {
            position: absolute;
            background: var(--white);
            border-radius: var(--radius);
            padding: 16px 20px;
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 12px;
            animation: float 3s ease-in-out infinite;
        }
        .hero-float-card.card-1 { bottom: 30px; left: -30px; }
        .hero-float-card.card-2 { top: 30px; right: -20px; }
        .hero-float-icon {
            width: 44px; height: 44px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .hero-float-icon.blue { background: var(--accent-glow); color: var(--accent); }
        .hero-float-icon.green { background: rgba(16,185,129,.12); color: var(--green); }
        .hero-float-card h4 { font-size: 14px; font-weight: 700; color: var(--text-dark); }
        .hero-float-card p { font-size: 11px; color: var(--text-muted); }

        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }

        /* ============================================================
           ABOUT
        ============================================================ */
        .about {
            padding: 100px 0;
            background: var(--white);
        }
        .about .container {
            display: flex;
            align-items: center;
            gap: 60px;
        }
        .about-image {
            flex: 1;
            position: relative;
        }
        .about-image img {
            border-radius: var(--radius-xl);
            box-shadow: var(--shadow-lg);
        }
        .about-stats-card {
            position: absolute;
            top: -20px;
            right: -20px;
            background: var(--white);
            border-radius: var(--radius);
            padding: 20px 28px;
            box-shadow: var(--shadow-lg);
            text-align: center;
        }
        .about-stats-card h3 {
            font-size: 36px;
            font-weight: 800;
            color: var(--accent);
        }
        .about-stats-card p {
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 600;
        }
        .about-content { flex: 1; }
        .section-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--accent);
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 12px;
        }
        .section-tag i { font-size: 10px; }
        .section-title {
            font-family: 'Playfair Display', serif;
            font-size: 38px;
            font-weight: 800;
            color: var(--text-dark);
            line-height: 1.2;
            margin-bottom: 20px;
        }
        .section-desc {
            font-size: 15px;
            line-height: 1.8;
            color: var(--text-body);
            margin-bottom: 28px;
        }
        .about-features {
            display: flex;
            flex-direction: column;
            gap: 14px;
            margin-bottom: 30px;
        }
        .about-feature-item {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-dark);
        }
        .about-feature-item i {
            width: 24px; height: 24px;
            background: var(--accent-glow);
            color: var(--accent);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            flex-shrink: 0;
        }
        .about-author {
            display: flex;
            align-items: center;
            gap: 14px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
        }
        .about-author-avatar {
            width: 50px; height: 50px;
            border-radius: 50%;
            background: var(--accent);
            color: var(--white);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 18px;
        }
        .about-author h4 { font-size: 15px; font-weight: 700; color: var(--text-dark); }
        .about-author p { font-size: 12px; color: var(--text-muted); }

        /* ============================================================
           SERVICES
        ============================================================ */
        .services {
            padding: 100px 0;
            background: var(--bg-light);
        }
        .section-header {
            text-align: center;
            margin-bottom: 60px;
        }
        .services-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
        }
        .service-card {
            background: var(--white);
            border-radius: var(--radius-lg);
            padding: 36px 28px;
            text-align: center;
            transition: var(--transition);
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }
        .service-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0;
            width: 100%; height: 4px;
            background: var(--accent);
            transform: scaleX(0);
            transition: var(--transition);
        }
        .service-card:hover {
            transform: translateY(-8px);
            box-shadow: var(--shadow-lg);
            border-color: transparent;
        }
        .service-card:hover::before { transform: scaleX(1); }
        .service-icon {
            width: 70px; height: 70px;
            background: var(--accent-glow);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            color: var(--accent);
            margin: 0 auto 20px;
            transition: var(--transition);
        }
        .service-card:hover .service-icon {
            background: var(--accent);
            color: var(--white);
        }
        .service-card h3 {
            font-size: 17px;
            font-weight: 700;
            color: var(--text-dark);
            margin-bottom: 10px;
        }
        .service-card p {
            font-size: 13px;
            line-height: 1.7;
            color: var(--text-muted);
        }

        /* ============================================================
           VIDEO / CTA BANNER
        ============================================================ */
        .video-section {
            position: relative;
            padding: 120px 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            text-align: center;
            overflow: hidden;
        }
        .video-section::before {
            content: '';
            position: absolute;
            inset: 0;
            background: url('assets/hero-bg.jpg') center/cover;
            opacity: 0.15;
        }
        .video-content {
            position: relative;
            z-index: 2;
        }
        .video-content .section-tag { color: rgba(255,255,255,.7); }
        .video-content h2 {
            font-family: 'Playfair Display', serif;
            font-size: 42px;
            font-weight: 800;
            color: var(--white);
            margin-bottom: 30px;
            line-height: 1.2;
        }
        .play-btn {
            width: 80px; height: 80px;
            background: var(--orange);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-size: 24px;
            cursor: pointer;
            transition: var(--transition);
            border: none;
            position: relative;
        }
        .play-btn::after {
            content: '';
            position: absolute;
            inset: -12px;
            border: 2px solid rgba(249,115,22,.4);
            border-radius: 50%;
            animation: pulse-ring 1.5s infinite;
        }
        .play-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 8px 30px rgba(249,115,22,.4);
        }
        @keyframes pulse-ring {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(1.4); opacity: 0; }
        }

        /* ============================================================
           WHY CHOOSE US
        ============================================================ */
        .why-us {
            padding: 100px 0;
            background: var(--white);
        }
        .why-us .container {
            display: flex;
            gap: 60px;
            align-items: center;
        }
        .why-us-content { flex: 1; }
        .why-us-image { flex: 1; }
        .why-us-image img {
            border-radius: var(--radius-xl);
            box-shadow: var(--shadow-lg);
        }
        .why-cards {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 36px;
        }
        .why-card {
            background: var(--bg-light);
            border-radius: var(--radius);
            padding: 24px 18px;
            text-align: center;
            transition: var(--transition);
            border: 1px solid transparent;
        }
        .why-card:hover {
            border-color: var(--accent);
            background: var(--white);
            box-shadow: var(--shadow-md);
        }
        .why-card-icon {
            width: 50px; height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            margin: 0 auto 12px;
        }
        .why-card-icon.blue { background: var(--accent-glow); color: var(--accent); }
        .why-card-icon.green { background: rgba(16,185,129,.1); color: var(--green); }
        .why-card-icon.orange { background: rgba(249,115,22,.1); color: var(--orange); }
        .why-card h4 { font-size: 13px; font-weight: 700; color: var(--text-dark); margin-bottom: 6px; }
        .why-card p { font-size: 11.5px; color: var(--text-muted); line-height: 1.6; }

        /* ============================================================
           PROCESS STEPS
        ============================================================ */
        .process {
            padding: 100px 0;
            background: var(--bg-light);
        }
        .process-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 32px;
            margin-bottom: 40px;
        }
        .process-card {
            text-align: center;
            position: relative;
        }
        .process-img {
            width: 180px; height: 180px;
            border-radius: 50%;
            object-fit: cover;
            margin: 0 auto 20px;
            border: 4px solid var(--white);
            box-shadow: var(--shadow-md);
        }
        .process-number {
            position: absolute;
            top: 0; right: calc(50% - 100px);
            width: 36px; height: 36px;
            background: var(--accent);
            color: var(--white);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 800;
            border: 3px solid var(--white);
        }
        .process-card h3 { font-size: 17px; font-weight: 700; color: var(--text-dark); margin-bottom: 8px; }
        .process-card p { font-size: 13px; color: var(--text-muted); line-height: 1.7; max-width: 280px; margin: 0 auto; }
        .process-buttons {
            display: flex;
            justify-content: center;
            gap: 16px;
        }
        .btn-primary-main {
            background: var(--accent);
            color: var(--white);
            padding: 14px 32px;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 700;
            border: none;
            cursor: pointer;
            transition: var(--transition);
        }
        .btn-primary-main:hover {
            background: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(37,99,235,.3);
        }
        .btn-outline-main {
            background: transparent;
            color: var(--accent);
            padding: 14px 32px;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 700;
            border: 2px solid var(--accent);
            cursor: pointer;
            transition: var(--transition);
        }
        .btn-outline-main:hover {
            background: var(--accent);
            color: var(--white);
        }

        /* ============================================================
           QUOTE FORM
        ============================================================ */
        .quote-section {
            padding: 100px 0;
            background: var(--accent);
            position: relative;
            overflow: hidden;
        }
        .quote-section::before {
            content: '';
            position: absolute;
            width: 400px; height: 400px;
            border-radius: 50%;
            background: rgba(255,255,255,.05);
            top: -100px; right: -100px;
        }
        .quote-section::after {
            content: '';
            position: absolute;
            width: 300px; height: 300px;
            border-radius: 50%;
            background: rgba(255,255,255,.03);
            bottom: -80px; left: -80px;
        }
        .quote-section .container {
            display: flex;
            align-items: center;
            gap: 60px;
            position: relative;
            z-index: 2;
        }
        .quote-content { flex: 1; }
        .quote-content .section-tag { color: rgba(255,255,255,.7); }
        .quote-content h2 {
            font-family: 'Playfair Display', serif;
            font-size: 38px;
            font-weight: 800;
            color: var(--white);
            line-height: 1.2;
            margin-bottom: 16px;
        }
        .quote-content p { color: rgba(255,255,255,.7); font-size: 15px; line-height: 1.7; }
        .quote-form-card {
            flex: 1;
            background: var(--white);
            border-radius: var(--radius-xl);
            padding: 40px;
            box-shadow: var(--shadow-xl);
        }
        .quote-form-card h3 {
            font-size: 20px;
            font-weight: 800;
            color: var(--text-dark);
            margin-bottom: 24px;
        }
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
            margin-bottom: 14px;
        }
        .form-row.single { grid-template-columns: 1fr; }
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 1.5px solid var(--border);
            border-radius: var(--radius);
            font-size: 14px;
            font-family: inherit;
            color: var(--text-dark);
            outline: none;
            transition: var(--transition);
            background: var(--bg-light);
        }
        .form-input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
            background: var(--white);
        }
        .form-input::placeholder { color: var(--text-muted); }
        .form-select {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2394a3b8' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 14px center;
            padding-right: 36px;
        }
        .btn-form-submit {
            width: 100%;
            padding: 14px;
            background: var(--orange);
            color: var(--white);
            border: none;
            border-radius: var(--radius);
            font-size: 15px;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            transition: var(--transition);
            margin-top: 8px;
        }
        .btn-form-submit:hover {
            background: var(--orange-light);
            transform: translateY(-2px);
        }

        /* ============================================================
           TESTIMONIALS
        ============================================================ */
        .testimonials {
            padding: 100px 0;
            background: var(--bg-light);
        }
        .testimonial-card {
            background: var(--white);
            border-radius: var(--radius-xl);
            padding: 40px;
            box-shadow: var(--shadow-md);
            max-width: 700px;
            margin: 0 auto;
            position: relative;
        }
        .testimonial-quote {
            position: absolute;
            top: 20px; right: 30px;
            font-size: 60px;
            color: var(--accent-glow);
            font-family: serif;
            line-height: 1;
        }
        .testimonial-stars {
            color: var(--gold);
            font-size: 14px;
            margin-bottom: 16px;
            display: flex;
            gap: 3px;
        }
        .testimonial-card > h4 {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-dark);
            margin-bottom: 12px;
        }
        .testimonial-text {
            font-size: 15px;
            line-height: 1.8;
            color: var(--text-body);
            margin-bottom: 24px;
            font-style: italic;
        }
        .testimonial-author {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .testimonial-avatar {
            width: 50px; height: 50px;
            border-radius: 50%;
            background: var(--accent);
            color: var(--white);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 18px;
        }
        .testimonial-author h5 {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-dark);
        }
        .testimonial-author span {
            font-size: 12px;
            color: var(--text-muted);
        }
        .testimonial-nav {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 24px;
        }
        .testimonial-dot {
            width: 10px; height: 10px;
            border-radius: 50%;
            background: var(--border);
            cursor: pointer;
            transition: var(--transition);
        }
        .testimonial-dot.active { background: var(--accent); width: 28px; border-radius: 5px; }

        /* ============================================================
           PLANS SECTION (was blog in template)
        ============================================================ */
        .plans-section {
            padding: 100px 0;
            background: var(--white);
        }
        .plans-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 28px;
        }
        .plan-card-new {
            background: var(--white);
            border-radius: var(--radius-xl);
            overflow: hidden;
            border: 1px solid var(--border);
            transition: var(--transition);
            position: relative;
        }
        .plan-card-new:hover {
            transform: translateY(-8px);
            box-shadow: var(--shadow-lg);
            border-color: transparent;
        }
        .plan-card-header {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            padding: 30px;
            text-align: center;
            position: relative;
        }
        .plan-card-new.popular .plan-card-header {
            background: linear-gradient(135deg, var(--orange), #e65100);
        }
        .plan-card-popular-tag {
            position: absolute;
            top: 14px; right: 14px;
            background: var(--orange);
            color: var(--white);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .plan-card-icon {
            width: 60px; height: 60px;
            background: rgba(255,255,255,.15);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            color: var(--white);
            margin: 0 auto 14px;
        }
        .plan-card-header h3 {
            font-size: 20px;
            font-weight: 800;
            color: var(--white);
            margin-bottom: 6px;
        }
        .plan-card-price {
            font-size: 28px;
            font-weight: 900;
            color: var(--white);
        }
        .plan-card-price small {
            font-size: 13px;
            font-weight: 500;
            opacity: .8;
            display: block;
        }
        .plan-card-body {
            padding: 28px;
        }
        .plan-card-features {
            margin-bottom: 24px;
        }
        .plan-card-features li {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13.5px;
            color: var(--text-body);
            padding: 8px 0;
            border-bottom: 1px solid var(--bg-gray);
        }
        .plan-card-features li:last-child { border-bottom: none; }
        .plan-card-features li i {
            color: var(--green);
            font-size: 13px;
            flex-shrink: 0;
        }
        .btn-plan {
            display: block;
            width: 100%;
            text-align: center;
            padding: 12px;
            background: var(--accent);
            color: var(--white);
            border: none;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            transition: var(--transition);
        }
        .btn-plan:hover {
            background: var(--primary);
            transform: translateY(-2px);
        }
        .plan-card-new.popular .btn-plan {
            background: var(--orange);
        }
        .plan-card-new.popular .btn-plan:hover {
            background: #c2410c;
        }

        /* ============================================================
           STATS COUNTER
        ============================================================ */
        .stats-banner {
            padding: 60px 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
            text-align: center;
        }
        .stat-item h3 {
            font-size: 40px;
            font-weight: 900;
            color: var(--white);
            margin-bottom: 6px;
        }
        .stat-item p {
            font-size: 13px;
            color: rgba(255,255,255,.7);
            font-weight: 500;
        }

        /* ============================================================
           NEWSLETTER
        ============================================================ */
        .newsletter {
            padding: 60px 0;
            background: var(--primary);
        }
        .newsletter .container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 30px;
        }
        .newsletter-info {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .newsletter-icon {
            width: 50px; height: 50px;
            background: rgba(255,255,255,.1);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            color: var(--orange);
            flex-shrink: 0;
        }
        .newsletter-info h3 {
            font-size: 18px;
            font-weight: 700;
            color: var(--white);
        }
        .newsletter-info p {
            font-size: 13px;
            color: rgba(255,255,255,.6);
        }
        .newsletter-form {
            display: flex;
            gap: 10px;
        }
        .newsletter-input {
            padding: 12px 20px;
            border: 2px solid rgba(255,255,255,.15);
            border-radius: var(--radius);
            background: rgba(255,255,255,.08);
            color: var(--white);
            font-size: 14px;
            font-family: inherit;
            outline: none;
            width: 300px;
            transition: var(--transition);
        }
        .newsletter-input::placeholder { color: rgba(255,255,255,.4); }
        .newsletter-input:focus {
            border-color: var(--accent-light);
            background: rgba(255,255,255,.12);
        }
        .newsletter-btn {
            padding: 12px 28px;
            background: var(--orange);
            color: var(--white);
            border: none;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 700;
            font-family: inherit;
            cursor: pointer;
            transition: var(--transition);
        }
        .newsletter-btn:hover { background: var(--orange-light); }

        /* ============================================================
           FOOTER
        ============================================================ */
        .footer {
            background: #060e1e;
            color: rgba(255,255,255,.7);
            padding: 70px 0 0;
        }
        .footer-grid {
            display: grid;
            grid-template-columns: 1.5fr 1fr 1fr 1fr;
            gap: 40px;
            padding-bottom: 50px;
            border-bottom: 1px solid rgba(255,255,255,.08);
        }
        .footer-brand h3 {
            font-size: 22px;
            font-weight: 800;
            color: var(--white);
            margin-bottom: 14px;
        }
        .footer-brand h3 span { color: var(--accent); }
        .footer-brand p {
            font-size: 13.5px;
            line-height: 1.8;
            margin-bottom: 18px;
        }
        .footer-social {
            display: flex;
            gap: 10px;
        }
        .footer-social a {
            width: 38px; height: 38px;
            border-radius: 10px;
            background: rgba(255,255,255,.06);
            display: flex;
            align-items: center;
            justify-content: center;
            color: rgba(255,255,255,.6);
            font-size: 14px;
            transition: var(--transition);
        }
        .footer-social a:hover {
            background: var(--accent);
            color: var(--white);
        }
        .footer-col h4 {
            font-size: 16px;
            font-weight: 700;
            color: var(--white);
            margin-bottom: 20px;
        }
        .footer-col li {
            margin-bottom: 10px;
        }
        .footer-col a {
            font-size: 13.5px;
            color: rgba(255,255,255,.6);
            transition: var(--transition);
        }
        .footer-col a:hover { color: var(--accent-light); padding-left: 4px; }
        .footer-col .contact-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            margin-bottom: 12px;
            font-size: 13.5px;
        }
        .footer-col .contact-item i {
            color: var(--accent-light);
            margin-top: 3px;
            flex-shrink: 0;
        }
        .footer-bottom {
            padding: 20px 0;
            text-align: center;
            font-size: 13px;
            color: rgba(255,255,255,.4);
        }

        /* ============================================================
           WHATSAPP
        ============================================================ */
        .whatsapp-float {
            position: fixed;
            bottom: 28px; right: 28px;
            width: 60px; height: 60px;
            background: #25D366;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-size: 28px;
            box-shadow: 0 4px 16px rgba(37,211,102,.4);
            z-index: 9999;
            transition: var(--transition);
        }
        .whatsapp-float:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 24px rgba(37,211,102,.5);
        }

        /* ============================================================
           RESPONSIVE
        ============================================================ */
        @media (max-width: 1024px) {
            .hero .container { flex-direction: column; text-align: center; }
            .hero-content { max-width: 100%; }
            .hero-buttons { justify-content: center; }
            .hero-image { max-width: 400px; }
            .about .container { flex-direction: column; }
            .why-us .container { flex-direction: column; }
            .quote-section .container { flex-direction: column; }
            .services-grid { grid-template-columns: repeat(2, 1fr); }
            .plans-grid { grid-template-columns: repeat(2, 1fr); }
            .hero h1 { font-size: 40px; }
        }

        @media (max-width: 768px) {
            .topbar { display: none; }
            .mobile-toggle { display: block; }
            .nav-links, .nav-right { display: none; }
            .nav-links.active {
                display: flex;
                flex-direction: column;
                position: absolute;
                top: 75px; left: 0;
                width: 100%;
                background: var(--white);
                padding: 20px;
                box-shadow: var(--shadow-lg);
                z-index: 999;
            }
            .nav-right.active {
                display: flex;
                flex-direction: column;
                padding: 0 20px 20px;
                position: absolute;
                top: calc(75px + var(--nav-links-height, 200px));
                left: 0; width: 100%;
                background: var(--white);
            }
            .hero h1 { font-size: 32px; }
            .hero { padding: 60px 0; min-height: auto; }
            .section-title { font-size: 28px; }
            .services-grid,
            .plans-grid,
            .process-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 20px; }
            .why-cards { grid-template-columns: 1fr; }
            .footer-grid { grid-template-columns: 1fr; }
            .newsletter .container { flex-direction: column; text-align: center; }
            .newsletter-form { flex-direction: column; width: 100%; }
            .newsletter-input { width: 100%; }
            .form-row { grid-template-columns: 1fr; }
            .hero-float-card { display: none; }
            .about-stats-card { position: static; margin-top: 16px; display: inline-block; }
        }
    </style>
</head>
<body>

<!-- ============================================================
     TOPBAR
============================================================ -->
<div class="topbar">
    <div class="container">
        <div class="topbar-left">
            <span><i class="fas fa-map-marker-alt"></i> Av. principal No. 123, San Critobal</span>
            <span><i class="fas fa-clock"></i> Lun - Vie: 8:00 AM - 6:00 PM</span>
        </div>
        <div class="topbar-right">
            <span><i class="fas fa-phone"></i> 809-555-5555</span>
            <span><i class="fas fa-envelope"></i> info@orthiis.com</span>
            <a href="https://www.facebook.com/orthiis" target="_blank"><i class="fab fa-facebook-f"></i></a>
            <a href="https://www.instagram.com/orthiis" target="_blank"><i class="fab fa-instagram"></i></a>
            <a href="https://www.x.com/orthiis" target="_blank"><i class="fab fa-twitter"></i></a>
        </div>
    </div>
</div>

<!-- ============================================================
     NAVBAR
============================================================ -->
<nav class="navbar" id="navbar">
    <div class="container">
        <a href="#inicio" class="nav-logo">
            <div class="nav-logo-icon"><i class="fas fa-shield-halved"></i></div>
            <div class="nav-logo-text">ORT<span>HIIS</span></div>
        </a>

        <div class="nav-links" id="navLinks">
            <a href="#inicio" class="active">Inicio</a>
            <a href="#nosotros">Nosotros</a>
            <a href="#servicios">Servicios</a>
            <a href="#planes">Planes</a>
            <a href="#proceso">Proceso</a>
            <a href="#contacto">Contacto</a>
            <a href="login.php">Login</a>
        </div>

        <div class="nav-right">
            <a href="tel:8095555555" class="nav-phone">
                <i class="fas fa-phone-volume"></i>
                809-555-5555
            </a>
            <a href="#contacto" class="nav-cta">Cotizar Ahora</a>
        </div>

        <button class="mobile-toggle" id="mobileToggle" aria-label="Menú">
            <i class="fas fa-bars"></i>
        </button>
    </div>
</nav>

<!-- ============================================================
     HERO
============================================================ -->
<section class="hero" id="inicio">
    <div class="container">
        <div class="hero-content" data-aos="fade-right">
            <div class="hero-badge"><i class="fas fa-star"></i> Seguros de Vida Confiables</div>
            <h1>Seguros Para Una<br><span>Mejor Vida Familiar.</span></h1>
            <p class="hero-desc">Brindamos tranquilidad y apoyo a las familias dominicanas con servicios funerarios de calidad, planes accesibles y atención profesional las 24 horas.</p>
            <div class="hero-buttons">
                <a href="#planes" class="btn-hero-primary"><i class="fas fa-arrow-right"></i> Conoce Nuestros Planes</a>
                <a href="#contacto" class="btn-hero-outline"><i class="fas fa-phone"></i> Contáctanos</a>
            </div>
        </div>

        <div class="hero-image" data-aos="fade-left">
            <img src="assets/hero-bg.jpg" alt="Familia protegida con ORTHIIS" style="width:100%; height:400px; object-fit:cover;">
            <div class="hero-float-card card-1">
                <div class="hero-float-icon blue"><i class="fas fa-shield-halved"></i></div>
                <div>
                    <h4>+1,300 Familias</h4>
                    <p>Protegidas con ORTHIIS</p>
                </div>
            </div>
            <div class="hero-float-card card-2" style="animation-delay:.5s;">
                <div class="hero-float-icon green"><i class="fas fa-heart"></i></div>
                <div>
                    <h4>Servicio 24/7</h4>
                    <p>Siempre a su lado</p>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ============================================================
     ABOUT
============================================================ -->
<section class="about" id="nosotros">
    <div class="container">
        <div class="about-image" data-aos="fade-right">
            <img src="assets/service-1.jpg" alt="Sobre ORTHIIS" style="width:100%; height:400px; object-fit:cover;">
            <div class="about-stats-card">
                <h3 data-counter="1300">0</h3>
                <p>Familias Protegidas</p>
            </div>
        </div>

        <div class="about-content" data-aos="fade-left">
            <div class="section-tag"><i class="fas fa-circle"></i> Sobre Nosotros</div>
            <h2 class="section-title">Somos una Empresa de Seguros Confiable y Profesional</h2>
            <p class="section-desc">ORTHIIS — Servicios Funerarios, es una empresa comprometida con brindar la mejor atención y tranquilidad a las familias dominicanas. Con más de 3 años de experiencia, ofrecemos planes de seguro de vida accesibles con cobertura completa.</p>

            <div class="about-features">
                <div class="about-feature-item"><i class="fas fa-check"></i> Cobertura desde 1 hasta 75 años</div>
                <div class="about-feature-item"><i class="fas fa-check"></i> Activación garantizada a los 5 meses</div>
                <div class="about-feature-item"><i class="fas fa-check"></i> Servicio funeral completo incluido</div>
                <div class="about-feature-item"><i class="fas fa-check"></i> Bonos en efectivo según el plan</div>
                <div class="about-feature-item"><i class="fas fa-check"></i> Atención profesional las 24 horas</div>
            </div>

            <div class="about-author">
                <div class="about-author-avatar">SF</div>
                <div>
                    <h4>ORTHIIS</h4>
                    <p>Servicios Funerarios — Bonao, RD</p>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ============================================================
     SERVICES
============================================================ -->
<section class="services" id="servicios">
    <div class="container">
        <div class="section-header" data-aos="fade-up">
            <div class="section-tag" style="justify-content:center;"><i class="fas fa-circle"></i> Nuestros Servicios</div>
            <h2 class="section-title">Cubrimos Todas las Áreas<br>de Servicios de Seguros</h2>
        </div>

        <div class="services-grid">
            <div class="service-card" data-aos="fade-up" data-aos-delay="0">
                <div class="service-icon"><i class="fas fa-shield-halved"></i></div>
                <h3>Seguro de Vida</h3>
                <p>Protección integral para usted y su familia con cobertura completa y planes accesibles.</p>
            </div>
            <div class="service-card" data-aos="fade-up" data-aos-delay="100">
                <div class="service-icon"><i class="fas fa-users"></i></div>
                <h3>Plan Familiar</h3>
                <p>Cobertura para toda la familia incluyendo dependientes y beneficiarios con bonos adicionales.</p>
            </div>
            <div class="service-card" data-aos="fade-up" data-aos-delay="200">
                <div class="service-icon"><i class="fas fa-user-clock"></i></div>
                <h3>Plan Geriátrico</h3>
                <p>Cobertura especial para personas mayores de 65 hasta 75 años con atención personalizada.</p>
            </div>
            <div class="service-card" data-aos="fade-up" data-aos-delay="300">
                <div class="service-icon"><i class="fas fa-hand-holding-heart"></i></div>
                <h3>Servicios Funerarios</h3>
                <p>Servicio funeral completo con instalaciones modernas y personal profesional capacitado.</p>
            </div>
        </div>
    </div>
</section>

<!-- ============================================================
     VIDEO / CTA SECTION
============================================================ -->
<section class="video-section">
    <div class="video-content" data-aos="zoom-in">
        <div class="section-tag"><i class="fas fa-circle"></i> Conozca ORTHIIS</div>
        <h2>Brindamos seguros<br>para el futuro de su familia</h2>
        <button class="play-btn" onclick="window.open('https://wa.me/18095555555','_blank')">
            <i class="fas fa-play" style="margin-left:3px;"></i>
        </button>
    </div>
</section>

<!-- ============================================================
     WHY CHOOSE US
============================================================ -->
<section class="why-us">
    <div class="container">
        <div class="why-us-content" data-aos="fade-right">
            <div class="section-tag"><i class="fas fa-circle"></i> Por Qué Elegirnos</div>
            <h2 class="section-title">Por qué debería elegir nuestros seguros</h2>
            <p class="section-desc">En ORTHIIS nos diferenciamos por ofrecer un servicio humano, transparente y accesible. Nuestro compromiso es brindarle la tranquilidad que usted y su familia merecen.</p>

            <div class="why-cards">
                <div class="why-card">
                    <div class="why-card-icon blue"><i class="fas fa-bolt"></i></div>
                    <h4>Proceso Rápido y Fácil</h4>
                    <p>Contratación simple sin trámites complicados ni requisitos excesivos.</p>
                </div>
                <div class="why-card">
                    <div class="why-card-icon green"><i class="fas fa-piggy-bank"></i></div>
                    <h4>Ahorre Su Dinero</h4>
                    <p>Planes desde cuotas accesibles mensuales con la mejor cobertura del mercado.</p>
                </div>
                <div class="why-card">
                    <div class="why-card-icon orange"><i class="fas fa-headset"></i></div>
                    <h4>Atención Sin Límites</h4>
                    <p>Servicio de atención disponible las 24 horas, los 7 días de la semana.</p>
                </div>
            </div>
        </div>

        <div class="why-us-image" data-aos="fade-left">
            <img src="assets/service-2.jpg" alt="Por qué ORTHIIS" style="width:100%; height:450px; object-fit:cover;">
        </div>
    </div>
</section>

<!-- ============================================================
     PROCESS STEPS
============================================================ -->
<section class="process" id="proceso">
    <div class="container">
        <div class="section-header" data-aos="fade-up">
            <div class="section-tag" style="justify-content:center;"><i class="fas fa-circle"></i> Cómo Funciona</div>
            <h2 class="section-title">Pasos para obtener<br>su seguro de vida</h2>
        </div>

        <div class="process-grid">
            <div class="process-card" data-aos="fade-up" data-aos-delay="0">
                <div class="process-number">1</div>
                <img src="assets/team-1.jpg" alt="Paso 1" class="process-img">
                <h3>Conozca a un asesor</h3>
                <p>Nuestro equipo de vendedores le visitará para explicarle todos los planes disponibles sin compromiso.</p>
            </div>
            <div class="process-card" data-aos="fade-up" data-aos-delay="100">
                <div class="process-number">2</div>
                <img src="assets/team-2.jpg" alt="Paso 2" class="process-img">
                <h3>Seleccione su plan</h3>
                <p>Elija entre nuestros planes Básico, Familiar o Premium según las necesidades de su familia.</p>
            </div>
            <div class="process-card" data-aos="fade-up" data-aos-delay="200">
                <div class="process-number">3</div>
                <img src="assets/team-3.jpg" alt="Paso 3" class="process-img">
                <h3>Obtenga su seguro</h3>
                <p>Firme su contrato, reciba su carnet y disfrute de la tranquilidad de estar protegido.</p>
            </div>
        </div>

        <div class="process-buttons" data-aos="fade-up">
            <a href="#contacto" class="btn-primary-main">Solicitar Información</a>
            <a href="tel:8095555555" class="btn-outline-main"><i class="fas fa-phone"></i> Llamar Ahora</a>
        </div>
    </div>
</section>

<!-- ============================================================
     QUOTE FORM
============================================================ -->
<section class="quote-section" id="contacto">
    <div class="container">
        <div class="quote-content" data-aos="fade-right">
            <div class="section-tag"><i class="fas fa-circle"></i> Cotización Gratis</div>
            <h2>Obtenga una cotización de seguro para comenzar</h2>
            <p>Complete el formulario y uno de nuestros asesores se comunicará con usted en menos de 24 horas para ofrecerle el plan ideal para su familia.</p>
        </div>

        <div class="quote-form-card" data-aos="fade-left">
            <h3>Solicite Su Cotización</h3>
            <form id="contactForm" onsubmit="enviarFormulario(event)">
                <div class="form-row">
                    <input type="text" class="form-input" placeholder="Nombre completo" name="nombre" required>
                    <input type="tel" class="form-input" placeholder="Teléfono" name="telefono" required>
                </div>
                <div class="form-row">
                    <input type="email" class="form-input" placeholder="Correo electrónico" name="email">
                    <input type="text" class="form-input" placeholder="Ciudad / Sector" name="ciudad">
                </div>
                <div class="form-row single">
                    <select class="form-input form-select" name="plan" id="plan" required>
                        <option value="">Seleccione un plan</option>
                        <option value="básico">Plan Básico — RD$30,000</option>
                        <option value="familiar">Plan Familiar — RD$35,000 + bono</option>
                        <option value="premium">Plan Premium — RD$40,000 + bono</option>
                        <option value="geriátrico">Plan Geriátrico</option>
                    </select>
                </div>
                <div class="form-row single">
                    <textarea class="form-input" rows="3" placeholder="Mensaje o consulta adicional..." name="mensaje" style="resize:vertical;"></textarea>
                </div>
                <button type="submit" class="btn-form-submit"><i class="fas fa-paper-plane" style="margin-right:8px;"></i>Enviar Solicitud</button>
            </form>
        </div>
    </div>
</section>

<!-- ============================================================
     TESTIMONIALS
============================================================ -->
<section class="testimonials">
    <div class="container">
        <div class="section-header" data-aos="fade-up">
            <div class="section-tag" style="justify-content:center;"><i class="fas fa-circle"></i> Testimonios</div>
            <h2 class="section-title">Lo que dicen nuestros clientes</h2>
        </div>

        <div class="testimonial-card" data-aos="fade-up">
            <div class="testimonial-quote">"</div>
            <div class="testimonial-stars">
                <i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>
            </div>
            <h4>Gran Experiencia!</h4>
            <p class="testimonial-text">ORTHIIS nos brindó un servicio excepcional. Desde el momento de la contratación hasta la atención recibida, todo fue profesional y humano. Nos sentimos respaldados en un momento difícil. Sin duda los recomiendo a todas las familias.</p>
            <div class="testimonial-author">
                <div class="testimonial-avatar">MR</div>
                <div>
                    <h5>María Rodríguez</h5>
                    <span>Cliente desde 2023</span>
                </div>
            </div>
        </div>

        <div class="testimonial-nav">
            <div class="testimonial-dot active"></div>
            <div class="testimonial-dot"></div>
            <div class="testimonial-dot"></div>
        </div>
    </div>
</section>

<!-- ============================================================
     PLANS
============================================================ -->
<section class="plans-section" id="planes">
    <div class="container">
        <div class="section-header" data-aos="fade-up">
            <div class="section-tag" style="justify-content:center;"><i class="fas fa-circle"></i> Nuestros Planes</div>
            <h2 class="section-title">Elige el plan perfecto para tu familia</h2>
        </div>

        <div class="plans-grid">
            <!-- Plan Básico -->
            <div class="plan-card-new" data-aos="fade-up" data-aos-delay="0">
                <div class="plan-card-header">
                    <div class="plan-card-icon"><i class="fas fa-shield-halved"></i></div>
                    <h3>Plan Básico</h3>
                    <div class="plan-card-price">RD$30,000<small>de cobertura</small></div>
                </div>
                <div class="plan-card-body">
                    <ul class="plan-card-features">
                        <li><i class="fas fa-check-circle"></i> Cobertura desde 1 hasta 65 años</li>
                        <li><i class="fas fa-check-circle"></i> Geriátrico hasta 75 años</li>
                        <li><i class="fas fa-check-circle"></i> Activación a los 5 meses</li>
                        <li><i class="fas fa-check-circle"></i> Servicio funeral completo</li>
                    </ul>
                    <button class="btn-plan" onclick="contactarPlan('básico')">Contratar Ahora</button>
                </div>
            </div>

            <!-- Plan Familiar -->
            <div class="plan-card-new popular" data-aos="fade-up" data-aos-delay="100">
                <div class="plan-card-header">
                    <div class="plan-card-popular-tag">Más Popular</div>
                    <div class="plan-card-icon"><i class="fas fa-users"></i></div>
                    <h3>Plan Familiar</h3>
                    <div class="plan-card-price">RD$35,000<small>+ bono de RD$10,000</small></div>
                </div>
                <div class="plan-card-body">
                    <ul class="plan-card-features">
                        <li><i class="fas fa-check-circle"></i> Cobertura desde 1 hasta 65 años</li>
                        <li><i class="fas fa-check-circle"></i> Geriátrico hasta 75 años</li>
                        <li><i class="fas fa-check-circle"></i> Activación a los 5 meses</li>
                        <li><i class="fas fa-check-circle"></i> Bono en efectivo adicional</li>
                        <li><i class="fas fa-check-circle"></i> Servicio funeral completo</li>
                    </ul>
                    <button class="btn-plan" onclick="contactarPlan('familiar')">Contratar Ahora</button>
                </div>
            </div>

            <!-- Plan Premium -->
            <div class="plan-card-new" data-aos="fade-up" data-aos-delay="200">
                <div class="plan-card-header">
                    <div class="plan-card-icon"><i class="fas fa-crown"></i></div>
                    <h3>Plan Premium</h3>
                    <div class="plan-card-price">RD$40,000<small>+ bono de RD$20,000</small></div>
                </div>
                <div class="plan-card-body">
                    <ul class="plan-card-features">
                        <li><i class="fas fa-check-circle"></i> Cobertura desde 1 hasta 65 años</li>
                        <li><i class="fas fa-check-circle"></i> Geriátrico hasta 75 años</li>
                        <li><i class="fas fa-check-circle"></i> Activación a los 5 meses</li>
                        <li><i class="fas fa-check-circle"></i> Bono en efectivo premium</li>
                        <li><i class="fas fa-check-circle"></i> Servicio funeral completo</li>
                        <li><i class="fas fa-check-circle"></i> Beneficios adicionales</li>
                    </ul>
                    <button class="btn-plan" onclick="contactarPlan('premium')">Contratar Ahora</button>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ============================================================
     STATS BANNER
============================================================ -->
<section class="stats-banner">
    <div class="container">
        <div class="stats-grid">
            <div class="stat-item" data-aos="fade-up">
                <h3><span data-counter="3">0</span>+</h3>
                <p>Años de Experiencia</p>
            </div>
            <div class="stat-item" data-aos="fade-up" data-aos-delay="100">
                <h3><span data-counter="1300">0</span>+</h3>
                <p>Clientes Satisfechos</p>
            </div>
            <div class="stat-item" data-aos="fade-up" data-aos-delay="200">
                <h3><span data-counter="3">0</span></h3>
                <p>Planes Disponibles</p>
            </div>
            <div class="stat-item" data-aos="fade-up" data-aos-delay="300">
                <h3>24/7</h3>
                <p>Atención Disponible</p>
            </div>
        </div>
    </div>
</section>

<!-- ============================================================
     NEWSLETTER
============================================================ -->
<section class="newsletter">
    <div class="container">
        <div class="newsletter-info">
            <div class="newsletter-icon"><i class="fas fa-envelope"></i></div>
            <div>
                <h3>Suscríbase a Nuestro Boletín</h3>
                <p>Reciba noticias, promociones y consejos sobre seguros de vida</p>
            </div>
        </div>
        <form class="newsletter-form" onsubmit="event.preventDefault(); alert('Suscripción exitosa!');">
            <input type="email" class="newsletter-input" placeholder="Ingrese su correo electrónico" required>
            <button type="submit" class="newsletter-btn"><i class="fas fa-paper-plane" style="margin-right:6px;"></i>Suscribirse</button>
        </form>
    </div>
</section>

<!-- ============================================================
     FOOTER
============================================================ -->
<footer class="footer">
    <div class="container">
        <div class="footer-grid">
            <div class="footer-brand">
                <h3>ORT<span>HIIS</span></h3>
                <p>Servicios Funerarios, brindando tranquilidad y apoyo a las familias dominicanas desde hace más de 3 años con servicios de calidad y atención profesional.</p>
                <div class="footer-social">
                    <a href="https://www.facebook.com/orthiis" target="_blank"><i class="fab fa-facebook-f"></i></a>
                    <a href="https://www.instagram.com/orthiis" target="_blank"><i class="fab fa-instagram"></i></a>
                    <a href="https://www.x.com/orthiis" target="_blank"><i class="fab fa-twitter"></i></a>
                    <a href="https://www.linkedin.com/orthiis" target="_blank"><i class="fab fa-linkedin-in"></i></a>
                </div>
            </div>

            <div class="footer-col">
                <h4>Explorar</h4>
                <ul>
                    <li><a href="#inicio">Inicio</a></li>
                    <li><a href="#nosotros">Sobre Nosotros</a></li>
                    <li><a href="#servicios">Servicios</a></li>
                    <li><a href="#planes">Planes</a></li>
                    <li><a href="login.php">Acceso al Sistema</a></li>
                </ul>
            </div>

            <div class="footer-col">
                <h4>Servicios</h4>
                <ul>
                    <li><a href="#planes">Plan Básico</a></li>
                    <li><a href="#planes">Plan Familiar</a></li>
                    <li><a href="#planes">Plan Premium</a></li>
                    <li><a href="#planes">Plan Geriátrico</a></li>
                    <li><a href="#contacto">Cotización Gratis</a></li>
                </ul>
            </div>

            <div class="footer-col">
                <h4>Contacto</h4>
                <div class="contact-item">
                    <i class="fas fa-map-marker-alt"></i>
                    <span>Av. principal No. 123, San Critobal</span>
                </div>
                <div class="contact-item">
                    <i class="fas fa-phone"></i>
                    <span>809-555-5555</span>
                </div>
                <div class="contact-item">
                    <i class="fas fa-envelope"></i>
                    <span>info@orthiis.com</span>
                </div>
                <div class="contact-item">
                    <i class="fas fa-clock"></i>
                    <span>Lun - Vie: 8:00 AM - 6:00 PM</span>
                </div>
            </div>
        </div>

        <div class="footer-bottom">
            <p>&copy; <?php echo date('Y'); ?> ORTHIIS — Servicios Funerarios. Todos los derechos reservados.</p>
        </div>
    </div>
</footer>

<!-- ============================================================
     WHATSAPP
============================================================ -->
<a href="https://wa.me/18095555555" class="whatsapp-float" target="_blank" title="Escríbenos por WhatsApp">
    <i class="fab fa-whatsapp"></i>
</a>

<!-- ============================================================
     SCRIPTS
============================================================ -->
<script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
<script>
// AOS Init
AOS.init({ duration: 800, once: true, offset: 80 });

// Navbar scroll effect
window.addEventListener('scroll', function() {
    const navbar = document.getElementById('navbar');
    navbar.classList.toggle('scrolled', window.scrollY > 50);
});

// Mobile toggle
document.getElementById('mobileToggle').addEventListener('click', function() {
    document.getElementById('navLinks').classList.toggle('active');
});

// Close mobile menu on link click
document.querySelectorAll('.nav-links a').forEach(function(link) {
    link.addEventListener('click', function() {
        document.getElementById('navLinks').classList.remove('active');
    });
});

// Active nav link on scroll
window.addEventListener('scroll', function() {
    const sections = document.querySelectorAll('section[id]');
    const scrollPos = window.scrollY + 100;
    sections.forEach(function(section) {
        const top = section.offsetTop;
        const height = section.offsetHeight;
        const id = section.getAttribute('id');
        const link = document.querySelector('.nav-links a[href="#' + id + '"]');
        if (link) {
            if (scrollPos >= top && scrollPos < top + height) {
                document.querySelectorAll('.nav-links a').forEach(function(a) { a.classList.remove('active'); });
                link.classList.add('active');
            }
        }
    });
});

// Counter animation
function animateCounter(el) {
    const target = parseInt(el.getAttribute('data-counter'));
    const duration = 2000;
    const step = target / duration * 16;
    let current = 0;
    const timer = setInterval(function() {
        current += step;
        if (current >= target) {
            clearInterval(timer);
            current = target;
        }
        el.textContent = Math.floor(current);
    }, 16);
}

const counterObserver = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
        if (entry.isIntersecting) {
            const counters = entry.target.querySelectorAll('[data-counter]');
            counters.forEach(function(counter) { animateCounter(counter); });
            counterObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.3 });

document.querySelectorAll('.stats-grid, .about-stats-card').forEach(function(el) {
    counterObserver.observe(el);
});

// Contact plan function
function contactarPlan(plan) {
    const planSelect = document.getElementById('plan');
    if (planSelect) {
        planSelect.value = plan;
    }
    document.querySelector('#contacto').scrollIntoView({ behavior: 'smooth' });
}

// Form submit
function enviarFormulario(e) {
    e.preventDefault();
    const form = e.target;
    const nombre = form.nombre.value;
    const telefono = form.telefono.value;
    const plan = form.plan.value;
    const mensaje = form.mensaje?.value || '';

    // Build WhatsApp message
    let waMsg = 'Hola ORTHIIS! Me interesa el *' + plan.charAt(0).toUpperCase() + plan.slice(1) + '*.\n\n';
    waMsg += '*Nombre:* ' + nombre + '\n';
    waMsg += '*Teléfono:* ' + telefono + '\n';
    if (mensaje) waMsg += '*Mensaje:* ' + mensaje + '\n';

    window.open('https://wa.me/18095555555?text=' + encodeURIComponent(waMsg), '_blank');
    form.reset();
}

// Testimonial dots interaction
document.querySelectorAll('.testimonial-dot').forEach(function(dot, i) {
    dot.addEventListener('click', function() {
        document.querySelectorAll('.testimonial-dot').forEach(function(d) { d.classList.remove('active'); });
        dot.classList.add('active');
    });
});
</script>

</body>
</html>