# rapport_pdf.py — Smart NetSec SOC — Rapport Professionnel
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# Palette SOC
C_DARK   = colors.HexColor('#0f172a')
C_BLUE   = colors.HexColor('#3b82f6')
C_GREEN  = colors.HexColor('#10b981')
C_ORANGE = colors.HexColor('#f59e0b')
C_RED    = colors.HexColor('#ef4444')
C_GRAY   = colors.HexColor('#64748b')
C_LIGHT  = colors.HexColor('#f1f5f9')
C_WHITE  = colors.white

def _styles():
    base = getSampleStyleSheet()
    styles = {
        'cover_title': ParagraphStyle('cover_title',
            fontSize=28, textColor=C_WHITE, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=8),
        'cover_sub': ParagraphStyle('cover_sub',
            fontSize=13, textColor=colors.HexColor('#94a3b8'),
            fontName='Helvetica', alignment=TA_CENTER, spaceAfter=4),
        'cover_meta': ParagraphStyle('cover_meta',
            fontSize=10, textColor=colors.HexColor('#64748b'),
            fontName='Helvetica', alignment=TA_CENTER),
        'section_title': ParagraphStyle('section_title',
            fontSize=14, textColor=C_BLUE, fontName='Helvetica-Bold',
            spaceBefore=16, spaceAfter=8,
            borderPad=4),
        'sub_title': ParagraphStyle('sub_title',
            fontSize=11, textColor=C_DARK, fontName='Helvetica-Bold',
            spaceBefore=10, spaceAfter=4),
        'body': ParagraphStyle('body',
            fontSize=9.5, textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica', spaceAfter=4, leading=14),
        'kpi_val': ParagraphStyle('kpi_val',
            fontSize=22, textColor=C_BLUE, fontName='Helvetica-Bold',
            alignment=TA_CENTER),
        'kpi_lbl': ParagraphStyle('kpi_lbl',
            fontSize=8, textColor=C_GRAY, fontName='Helvetica',
            alignment=TA_CENTER),
        'footer': ParagraphStyle('footer',
            fontSize=8, textColor=C_GRAY, fontName='Helvetica',
            alignment=TA_CENTER),
    }
    return styles


def _page_header_footer(canvas, doc):
    """En-tête et pied de page sur chaque page (sauf couverture)."""
    if doc.page == 1:
        return
    canvas.saveState()
    W = A4[0]
    # Header
    canvas.setFillColor(C_DARK)
    canvas.rect(0, A4[1]-20*mm, W, 20*mm, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE)
    canvas.setFont('Helvetica-Bold', 9)
    canvas.drawString(15*mm, A4[1]-13*mm, 'Smart NetSec SOC — Rapport de Sécurité')
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor('#94a3b8'))
    canvas.drawRightString(W-15*mm, A4[1]-13*mm,
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
    # Footer
    canvas.setFillColor(C_LIGHT)
    canvas.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(C_GRAY)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(15*mm, 4*mm, 'CONFIDENTIEL — Usage interne uniquement')
    canvas.drawRightString(W-15*mm, 4*mm, f'Page {doc.page}')
    canvas.restoreState()


def _cover_page(story, st, stats, now):
    """Page de couverture premium."""
    from reportlab.platypus import Table as T, TableStyle as TS

    W, H = A4
    # Fond noir
    story.append(Table(
        [['']],
        colWidths=[W - 40*mm],
        rowHeights=[45*mm],
        style=TS([
            ('BACKGROUND', (0,0), (-1,-1), C_DARK),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [C_DARK]),
        ])
    ))

    # Titre
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph('🛡️ Smart NetSec SOC', st['cover_title']))
    story.append(Paragraph('Security Operations Center', st['cover_sub']))
    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width='80%', color=C_BLUE, thickness=1.5, spaceAfter=8))
    story.append(Paragraph('RAPPORT DE SÉCURITÉ', ParagraphStyle(
        'rt', fontSize=16, textColor=C_BLUE, fontName='Helvetica-Bold',
        alignment=TA_CENTER)))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f"Généré le {now.strftime('%A %d %B %Y à %H:%M')}",
                           st['cover_meta']))
    story.append(Paragraph(f"Période : {(now).strftime('%d/%m/%Y')}",
                           st['cover_meta']))
    story.append(Spacer(1, 8*mm))

    # KPIs couverture
    kpi_data = [
        [Paragraph(str(stats.get('nb_appareils',0)), st['kpi_val']),
         Paragraph(str(stats.get('nb_alertes',0)), ParagraphStyle(
             'kv2',fontSize=22,textColor=C_RED,fontName='Helvetica-Bold',alignment=TA_CENTER)),
         Paragraph(str(len(__import__('backend.database.repositories',fromlist=['get_blocages']).get_blocages())), ParagraphStyle(
             'kv3',fontSize=22,textColor=C_ORANGE,fontName='Helvetica-Bold',alignment=TA_CENTER)),
         Paragraph(str(stats.get('score_moyen',0))+'/100', ParagraphStyle(
             'kv4',fontSize=22,textColor=C_GREEN,fontName='Helvetica-Bold',alignment=TA_CENTER))],
        [Paragraph('DEVICES', st['kpi_lbl']),
         Paragraph('ALERTES', st['kpi_lbl']),
         Paragraph('BLOQUÉES', st['kpi_lbl']),
         Paragraph('SCORE', st['kpi_lbl'])],
    ]
    kpi_table = Table(kpi_data, colWidths=[40*mm]*4,
                      rowHeights=[18*mm, 8*mm])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#1e293b')),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#1e293b')]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#334155')),
        ('INNERGRID', (0,0), (-1,-1), 0.3, colors.HexColor('#334155')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(kpi_table)
    story.append(PageBreak())


def _section(story, st, title):
    story.append(HRFlowable(width='100%', color=C_BLUE, thickness=0.5, spaceBefore=6))
    story.append(Paragraph(f'■ {title}', st['section_title']))


def _kpi_row(story, items):
    """Ligne de KPIs colorés."""
    cells  = [[Paragraph(str(v), ParagraphStyle('kv',fontSize=18,textColor=c,
               fontName='Helvetica-Bold',alignment=TA_CENTER)),
               Paragraph(lbl, ParagraphStyle('kl',fontSize=8,textColor=C_GRAY,
               alignment=TA_CENTER))]
              for lbl,v,c in items]
    flat   = [row for pair in cells for row in pair]
    t = Table([flat[:len(items)], flat[len(items):]],
              colWidths=[40*mm]*len(items),
              rowHeights=[16*mm, 8*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_LIGHT),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.2, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def generer_rapport(output_path=None):
    from backend.database import repositories as repo
    from backend.database.db import init_db
    init_db()

    if not output_path:
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "rapport_securite.pdf"
        )

    now    = datetime.now()
    stats  = repo.get_dashboard_stats()
    apps   = repo.get_appareils()
    alerts = repo.get_alertes(limit=50)
    scans  = repo.get_scans(limit=10)
    blocs  = repo.get_blocages(actif=True)
    wl     = repo.get_whitelist()
    snort  = repo.get_snort_alertes(limit=30)
    snort_s= repo.get_snort_stats()
    rules  = repo.get_fw_rules()

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=25*mm, bottomMargin=18*mm,
        title="Rapport SOC Smart NetSec",
        author="Smart NetSec SOC Platform",
    )

    st    = _styles()
    story = []

    # ── COUVERTURE ──
    _cover_page(story, st, stats, now)

    # ── RÉSUMÉ EXÉCUTIF ──
    _section(story, st, 'Résumé Exécutif')
    score = stats.get('score_moyen',0)
    niveau_txt = 'FAIBLE RISQUE' if score>=80 else ('RISQUE MODÉRÉ' if score>=60 else 'RISQUE ÉLEVÉ')
    col_score  = C_GREEN if score>=80 else (C_ORANGE if score>=60 else C_RED)
    story.append(Paragraph(
        f"Ce rapport présente l'état de sécurité du réseau au {now.strftime('%d/%m/%Y')}. "
        f"Le score de sécurité global est de <b>{score}/100</b>, ce qui indique un niveau "
        f"<b>{niveau_txt}</b>. "
        f"Un total de <b>{stats.get('nb_appareils',0)} appareils</b> ont été détectés, "
        f"dont <b>{stats.get('nb_danger',0)} en état critique</b>. "
        f"Le système a enregistré <b>{stats.get('nb_alertes',0)} alertes sécurité</b> "
        f"et <b>{snort_s.get('total',0)} alertes IDS Snort</b>.", st['body']))
    story.append(Spacer(1,4))

    _kpi_row(story, [
        ('Devices', stats.get('nb_appareils',0), C_BLUE),
        ('Score Global', f"{score}/100", col_score),
        ('Alertes', stats.get('nb_alertes',0), C_RED),
        ('IPs Bloquées', len(blocs), C_ORANGE),
    ])
    story.append(Spacer(1,6))

    # ── INVENTAIRE DEVICES ──
    _section(story, st, 'Inventaire des Appareils')
    _kpi_row(story, [
        ('Total', stats.get('nb_appareils',0), C_BLUE),
        ('Safe ≥80', stats.get('nb_safe',0), C_GREEN),
        ('Medium 50-79', stats.get('nb_medium',0), C_ORANGE),
        ('Danger <50', stats.get('nb_danger',0), C_RED),
    ])
    story.append(Spacer(1,6))

    if apps:
        dev_data = [['IP', 'TYPE', 'MAC', 'VENDOR', 'SCORE', 'NIVEAU']]
        for a in apps[:30]:
            sc = a.get('score',100)
            nv = 'SAFE' if sc>=80 else ('MEDIUM' if sc>=50 else 'DANGER')
            dev_data.append([
                a.get('ip','—'), a.get('type_appareil','—')[:15],
                a.get('mac','—')[:17], a.get('vendor',a.get('fabricant','—'))[:15],
                str(sc), nv
            ])
        dev_table = Table(dev_data,
            colWidths=[32*mm,30*mm,35*mm,30*mm,16*mm,20*mm])
        dev_style = [
            ('BACKGROUND', (0,0), (-1,0), C_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), C_WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.25, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]
        # Coloriser colonne NIVEAU
        for i, row in enumerate(dev_data[1:], 1):
            nv = row[5]
            col = C_GREEN if nv=='SAFE' else (C_ORANGE if nv=='MEDIUM' else C_RED)
            dev_style.append(('TEXTCOLOR', (5,i), (5,i), col))
            dev_style.append(('FONTNAME', (5,i), (5,i), 'Helvetica-Bold'))
        dev_table.setStyle(TableStyle(dev_style))
        story.append(dev_table)
    else:
        story.append(Paragraph('Aucun appareil enregistré — lancez un scan.', st['body']))

    story.append(PageBreak())

    # ── ALERTES SÉCURITÉ ──
    _section(story, st, 'Alertes Sécurité')
    _kpi_row(story, [
        ('Total', stats.get('nb_alertes',0), C_BLUE),
        ('Critiques', stats.get('nb_alertes_high',0), C_RED),
        ('Snort IDS', snort_s.get('total',0), C_ORANGE),
        ('Snort Critical', snort_s.get('critical',0), C_RED),
    ])
    story.append(Spacer(1,6))

    if alerts:
        al_data = [['DATE', 'IP', 'TYPE', 'MESSAGE', 'NIVEAU']]
        for a in alerts[:20]:
            al_data.append([
                (a.get('date_alerte','')[:16] or '—'),
                a.get('ip','—'), a.get('type_alerte','—')[:12],
                a.get('message','—')[:35], a.get('niveau','—')
            ])
        al_t = Table(al_data, colWidths=[30*mm,28*mm,25*mm,60*mm,20*mm])
        al_style = [
            ('BACKGROUND', (0,0), (-1,0), C_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), C_WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.2, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]
        for i, row in enumerate(al_data[1:], 1):
            nv = row[4]
            col = C_RED if nv in ('CRITICAL','HIGH') else (C_ORANGE if nv=='MEDIUM' else C_GRAY)
            al_style.append(('TEXTCOLOR', (4,i), (4,i), col))
            al_style.append(('FONTNAME', (4,i), (4,i), 'Helvetica-Bold'))
        al_t.setStyle(TableStyle(al_style))
        story.append(al_t)
    else:
        story.append(Paragraph('Aucune alerte enregistrée.', st['body']))

    story.append(PageBreak())

    # ── ALERTES SNORT IDS ──
    _section(story, st, 'Alertes IDS — Snort 3')
    if snort:
        sn_data = [['TIMESTAMP','SRC IP','DST IP','PROTO','SIGNATURE','NIVEAU']]
        for a in snort[:20]:
            sn_data.append([
                (a.get('timestamp','')[:16] or '—'),
                a.get('src_ip','—'), a.get('dst_ip',a.get('dest_ip','—')),
                a.get('protocole','—'),
                a.get('message','—')[:30], a.get('niveau','—')
            ])
        sn_t = Table(sn_data, colWidths=[28*mm,26*mm,26*mm,14*mm,52*mm,17*mm])
        sn_style = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#7c3aed')),
            ('TEXTCOLOR', (0,0), (-1,0), C_WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.2, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]
        for i, row in enumerate(sn_data[1:], 1):
            nv = row[5]
            col = C_RED if nv in ('CRITICAL','HIGH') else (C_ORANGE if nv=='MEDIUM' else C_GRAY)
            sn_style.append(('TEXTCOLOR', (5,i), (5,i), col))
            sn_style.append(('FONTNAME', (5,i), (5,i), 'Helvetica-Bold'))
        sn_t.setStyle(TableStyle(sn_style))
        story.append(sn_t)
    else:
        story.append(Paragraph('Aucune alerte Snort.', st['body']))

    story.append(PageBreak())

    # ── FIREWALL ──
    _section(story, st, 'Firewall nftables')
    _kpi_row(story, [
        ('IPs Bloquées', len(blocs), C_RED),
        ('Whitelist', len(wl), C_GREEN),
        ('Règles actives', len(rules), C_BLUE),
        ('Scans', stats.get('nb_scans',0), C_GRAY),
    ])
    story.append(Spacer(1,6))

    if blocs:
        story.append(Paragraph('<b>IPs Bloquées actives</b>', st['sub_title']))
        bl_data = [['IP', 'RAISON', 'NIVEAU', 'TYPE', 'DATE']]
        for b in blocs[:15]:
            bl_data.append([
                b.get('ip','—'), b.get('raison','—')[:30],
                b.get('niveau','—'),
                'AUTO' if b.get('auto_block') else 'Manuel',
                (b.get('date_blocage','')[:16] or '—'),
            ])
        bl_t = Table(bl_data, colWidths=[28*mm,55*mm,20*mm,18*mm,30*mm])
        bl_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_RED),
            ('TEXTCOLOR', (0,0), (-1,0), C_WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.2, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(bl_t)
        story.append(Spacer(1,6))

    # ── SCANS ──
    _section(story, st, 'Historique des Scans Réseau')
    if scans:
        sc_data = [['ID', 'DATE', 'PLAGE IP', 'APPAREILS', 'DURÉE', 'LANCÉ PAR']]
        for s in scans:
            sc_data.append([
                f"#{s.get('id','—')}",
                (s.get('date_scan','')[:16] or '—'),
                f"{s.get('ip_debut','?')} → {s.get('ip_fin','?')}",
                str(s.get('nb_appareils',0)),
                f"{s.get('duree_sec',0):.1f}s",
                s.get('lance_par','system'),
            ])
        sc_t = Table(sc_data, colWidths=[14*mm,32*mm,50*mm,22*mm,16*mm,25*mm])
        sc_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), C_WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_WHITE, C_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.2, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(sc_t)

    # ── PIED DE PAGE FINAL ──
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width='100%', color=C_BLUE, thickness=0.5))
    story.append(Spacer(1,4))
    story.append(Paragraph(
        f'Smart NetSec SOC Platform — Rapport confidentiel — {now.strftime("%d/%m/%Y")}',
        st['footer']))
    story.append(Paragraph(
        'MRINO | BOUZIDI — Projet de fin d\'études en Cybersécurité',
        st['footer']))

    doc.build(story, onFirstPage=_page_header_footer,
              onLaterPages=_page_header_footer)
    return output_path
