
import markdown
from xhtml2pdf import pisa
import os

def convert_md_to_pdf(source_md, output_pdf):
    # 1. Read Markdown
    with open(source_md, 'r', encoding='utf-8') as f:
        md_text = f.read()
        
    # 2. Convert to HTML
    html_content = markdown.markdown(md_text)
    
    # 3. Add styling (CSS) for professional look
    full_html = f"""
    <html>
    <head>
    <style>
        body {{
            font-family: Helvetica, Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.5;
            color: #333;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #55efc4;
            padding-bottom: 5px;
            font-size: 24pt;
        }}
        h2 {{
            color: #16a085;
            font-size: 18pt;
            margin-top: 20px;
        }}
        h3 {{
            color: #2980b9;
            font-size: 14pt;
        }}
        pre {{
            background-color: #f7f9fa;
            border: 1px solid #e1e8ed;
            padding: 10px;
            font-family: monospace;
            font-size: 9pt;
            border-radius: 4px;
        }}
        code {{
            background-color: #f7f9fa;
            font-family: monospace;
            padding: 2px 4px;
        }}
        blockquote {{
            background-color: #fff9db;
            border-left: 5px solid #f1c40f;
            padding: 10px;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            font-size: 8pt;
            color: #666;
            margin-top: 50px;
        }}
    </style>
    </head>
    <body>
        {html_content}
        <div class="footer">Generated automatically for retail distribution.</div>
    </body>
    </html>
    """
    
    # 4. Write PDF
    with open(output_pdf, "wb") as result_file:
        pisa_status = pisa.CreatePDF(full_html, dest=result_file)
        
    if pisa_status.err:
        print(f"Error converting to PDF: {pisa_status.err}")
    else:
        print(f"Successfully created: {output_pdf}")

if __name__ == "__main__":
    convert_md_to_pdf("EKA_DASHBOARD_MANUAL.md", "EKA_DASHBOARD_MANUAL.pdf")
