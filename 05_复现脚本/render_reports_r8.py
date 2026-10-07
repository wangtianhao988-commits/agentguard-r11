from pathlib import Path
import subprocess
import fitz
import json
import re

ROOT = Path(__file__).resolve().parents[1]
QA = ROOT/'07_修复验证/pdf_qa'
QA.mkdir(exist_ok=True)
FILES = ['R8_增强作品与检测报告','R8_技术说明书']
css = '''
@font-face {font-family: Song; src: url(simsun.ttc);}
pre {white-space:pre-wrap;}
body {font-family: Song; font-size:10.5pt; line-height:1.35; color:#111;}
h1 {font-family:Song; font-size:18pt; text-align:center; margin-bottom:18pt;}
h2 {font-size:14pt; margin-top:15pt; margin-bottom:8pt;}
h3 {font-size:12pt; margin-top:12pt;}
h2,h3 {page-break-after:avoid;}
p {margin-top:0; margin-bottom:9pt;}
table {border-collapse:collapse; width:100%; font-size:9pt; line-height:1.4; margin-bottom:12pt;}
td,th {border:0.5pt solid #777; padding:4pt; vertical-align:top;}
th {font-weight:bold;}
code {font-family:Song; font-size:10pt;}
li {margin-bottom:7pt;}
'''
summary = []
for name in FILES:
    source = ROOT/'01_交付文档'/(name+'.md')
    html = subprocess.run(['pandoc',str(source),'-f','gfm','-t','html'],
                          capture_output=True,check=True).stdout.decode('utf-8')
    html = re.sub(r'<h3([^>]*)>(3\.5)', r'<h3\1 style="page-break-before:always">\2', html)
    chunks = [html]
    if name == 'R8_增强作品与检测报告':
        headings = list(re.finditer(r'<h2[^>]*>',html))
        cuts = [headings[2].start(), headings[3].start()]
        chunks = [html[:cuts[0]],html[cuts[0]:cuts[1]],html[cuts[1]:]]
    if name == 'R8_技术说明书':
        headings=list(re.finditer(r'<h2[^>]*>',html))
        cuts=[headings[2].start(),headings[4].start()]
        chunks=[html[:cuts[0]],html[cuts[0]:cuts[1]],html[cuts[1]:]]
    output = source.with_suffix('.pdf')
    writer = fitz.DocumentWriter(str(output))
    mediabox = fitz.paper_rect('a4')
    def page_rect(number, filled):
        return mediabox, fitz.Rect(60,54,mediabox.width-60,mediabox.height-58), None
    for chunk in chunks:
        story = fitz.Story(html=chunk,user_css=css,archive=fitz.Archive('C:/Windows/Fonts'))
        story.write(writer,page_rect)
    writer.close()
    del writer  # Release the Windows file handle before replacing optimized output.
    doc = fitz.open(output)
    doc.set_metadata({'title':name,'author':'','creator':'','producer':''})
    for index,page in enumerate(doc):
        page.insert_text((mediabox.width/2-12,mediabox.height-30),str(index+1),fontsize=9)
    doc.subset_fonts()
    optimized = output.with_name(output.stem+'.optimized.pdf')
    doc.save(optimized,garbage=4,deflate=True)
    texts = '\n'.join(p.get_text() for p in doc)
    assert len(texts)>1000 and '风险' in texts, 'Missing Chinese text'
    for i,page in enumerate(doc):
        page.get_pixmap(matrix=fitz.Matrix(1,1)).save(QA/(name+f'_{i+1}.png'))
        for block in page.get_text('blocks'):
            assert block[0]>=45 and block[2]<=mediabox.width-40, (name,i,block[:4])
    summary.append({'name':name,'pages':len(doc),'text_characters':len(texts)})
    doc.close()
    optimized.replace(output)
(QA/'render_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(summary,ensure_ascii=False))
