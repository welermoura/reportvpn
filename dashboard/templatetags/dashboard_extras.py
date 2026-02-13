from django import template

register = template.Library()

@register.simple_tag(takes_context=True)
def param_replace(context, **kwargs):
    d = context['request'].GET.copy()
    for k, v in kwargs.items():
        d[k] = v
    for k in [k for k, v in d.items() if not v]:
        del d[k]
    return d.urlencode()

@register.filter
def format_duration(seconds):
    if not seconds:
        return "-"
    try:
        seconds = int(seconds)
    except:
        return "-"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

@register.filter
def format_volume(bytes_val):
    if not bytes_val:
        return "-"
    try:
        bytes_val = int(bytes_val)
    except:
        return "-"
    
    gb = bytes_val / (1024 * 1024 * 1024)
    if gb >= 1:
        return f"{gb:.2f} GB"
    mb = bytes_val / (1024 * 1024)
    return f"{mb:.2f} MB"
