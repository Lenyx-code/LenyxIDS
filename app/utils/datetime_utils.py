from datetime import datetime
class DatetimeUtils:
    def get_format_now():
        date_time = datetime.now()
        now = date_time.replace(microsecond=0)
        return now