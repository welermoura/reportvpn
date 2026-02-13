from django.http import HttpResponse
from io import BytesIO

def export_to_xlsx(queryset, filename, headers, field_mapping):
    """
    Generates an XLSX file from a queryset.
    
    :param queryset: The Django queryset to export.
    :param filename: The name of the file (e.g., 'report.xlsx').
    :param headers: List of column headers (e.g., ['Date', 'User']).
    :param field_mapping: List of model fields or callables corresponding to headers.
    """
    try:
        import openpyxl
        from openpyxl.utils import get_column_letter
    except ImportError:
        return HttpResponse("Library 'openpyxl' not installed.", status=500)
    except Exception as e:
        return HttpResponse(f"Error loading openpyxl: {str(e)}", status=500)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Report"
    
    # Write Header
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.value = header
        cell.font = openpyxl.styles.Font(bold=True)
        
    # Write Data
    for row_num, obj in enumerate(queryset, 2):
        for col_num, field in enumerate(field_mapping, 1):
            if callable(field):
                val = field(obj)
            else:
                # Handle nested fields (e.g., 'user.username') or simple fields
                val = obj
                for attr in field.split('.'):
                    val = getattr(val, attr, '')
                    if val is None: break
            
            # Formatting
            if isinstance(val, (int, float)):
                pass # Default is fine
            else:
                val = str(val) if val is not None else ''
                
            ws.cell(row=row_num, column=col_num).value = val
            
    # Auto-adjust column width
    for column_cells in ws.columns:
        length = max(len(str(cell.value) or "") for cell in column_cells)
        ws.column_dimensions[get_column_letter(column_cells[0].column)].width = length + 2
        
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    response = HttpResponse(
        output.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
