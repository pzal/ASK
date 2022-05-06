import {DateTime} from 'luxon'

export const DATE_FORMAT = 'dd/LL/yyyy'
export const HOUR_FORMAT = 'HH:mm'

export const DATETIME_FORMAT = `${DATE_FORMAT} ${HOUR_FORMAT}`

// export const getHour = hourString =>
//   DateTime.fromFormat(hourString, HOUR_FORMAT)
// export const getDate = dateString =>
//   DateTime.fromFormat(dateString, DATE_FORMAT)
// export const getDatetime = datetimeString =>
//   DateTime.fromFormat(datetimeString, DATETIME_FORMAT)
