import React, {Fragment} from 'react'
import Button from '@material-ui/core/Button'
import Grid from '@material-ui/core/Grid'
import DownloadIcon from '@material-ui/icons/GetApp'
import styled from 'styled-components'
import {useApiGet} from '../utils/api'
import {useParams, useHistory, Redirect} from 'react-router-dom'
import CircularProgress from '@material-ui/core/CircularProgress'
import {DateTime} from 'luxon'
import {DATETIME_FORMAT} from '../utils/date'

const ContentWrapper = styled.div`
  max-width: 700px;
`

const LabelWrapper = styled.div`
  color: rgb(152, 152, 152);
  text-transform: uppercase;
  font-size: 0.7rem;
  margin-bottom: -0.5rem;
  margin-top: 0.5rem;
`

interface Params {
  transferId: string
}

interface User {
  id: any
  email: string
  account_set: any[]
}

interface Account {
  id: any
  account_number: string
}

interface Contact {
  id: any
  user: any
  name: string
  account_number: string
}

interface TransferConfirmation {
  id: any
  file?: string
}

interface Transfer {
  id: any
  sender_user: User
  sender_account: Account
  recipient: Contact
  title: string
  amount: string
  pending: boolean
  date_created: string
  frozen_account_number?: string
  date_confirmed?: string
  transferconfirmation?: TransferConfirmation
  failed: boolean
}

export default function TransferDetailsPage() {
  const {transferId} = useParams<Params>()
  const history = useHistory()
  const {data, isPending, isRejected} = useApiGet<Transfer>(
    `${process.env.REACT_APP_API_URL}/transfers/${transferId}/?full_serializer=true`,
  )
  const {data: me, isPending: isMePending} = useApiGet<User>(
    `${process.env.REACT_APP_API_URL}/users/me/`,
  )

  if (isPending || isMePending) {
    return <CircularProgress />
  }

  if (isRejected) {
    return <Redirect to="/transfers/all" />
  }

  const outgoing = me?.id === data?.sender_user.id
  const getStatus = () => {
    if (data?.pending) {
      return 'Oczekujący'
    }

    if (data?.failed) {
      return 'Nieudany'
    }

    return 'Zrealizowany'
  }

  return (
    <Fragment>
      <ContentWrapper>
        <Grid container direction="column" spacing={2}>
          <Grid item>
            <LabelWrapper>Typ przelewu</LabelWrapper>
          </Grid>
          <Grid item>{outgoing ? 'Wychodzący' : 'Przychodzący'}</Grid>

          {outgoing && (
            <Fragment>
              <Grid item>
                <LabelWrapper>Odbiorca</LabelWrapper>
              </Grid>
              <Grid item>
                {data?.recipient.name} ({data?.frozen_account_number})
              </Grid>
            </Fragment>
          )}

          <Grid item>
            <LabelWrapper>Tytuł</LabelWrapper>
          </Grid>
          <Grid item>{data?.title}</Grid>

          <Grid item>
            <LabelWrapper>Kwota</LabelWrapper>
          </Grid>
          <Grid item>{data?.amount}</Grid>

          <Grid item>
            <LabelWrapper>Data realizacji</LabelWrapper>
          </Grid>
          <Grid item>
            {data?.date_confirmed &&
              DateTime.fromISO(data.date_confirmed).toFormat(DATETIME_FORMAT)}
          </Grid>

          <Grid item>
            <LabelWrapper>Status</LabelWrapper>
          </Grid>
          <Grid item>
            <span style={{color: getStatus() === 'Nieudany' ? 'red' : undefined}}>
              {getStatus()}
            </span>
          </Grid>

          {data?.transferconfirmation?.file && (
            <Grid item>
              <a
                download="confirmation.pdf"
                target="_blank"
                href={data?.transferconfirmation.file}
              >
                <Button
                  variant="contained"
                  color="primary"
                  size="large"
                  startIcon={<DownloadIcon />}
                >
                  Pobierz potwierdzenie
                </Button>
              </a>
            </Grid>
          )}
        </Grid>
      </ContentWrapper>
    </Fragment>
  )
}
