import React, {Fragment} from 'react'
import {Link} from 'react-router-dom'
import Typography from '@material-ui/core/Typography'
import List from '@material-ui/core/List'
import ListItem from '@material-ui/core/ListItem'
import ListItemAvatar from '@material-ui/core/ListItemAvatar'
import Button from '@material-ui/core/Button'
import Grid from '@material-ui/core/Grid'
import ListItemText from '@material-ui/core/ListItemText'
import Avatar from '@material-ui/core/Avatar'
import PersonAddIcon from '@material-ui/icons/PersonAdd'
import CircularProgress from '@material-ui/core/CircularProgress'
import DoubleArrowIcon from '@material-ui/icons/DoubleArrow'
import ArrowForwardIcon from '@material-ui/icons/ArrowForward'
import ArrowDownwardIcon from '@material-ui/icons/ArrowDownward'
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction'
import IconButton from '@material-ui/core/IconButton'
import InfoIcon from '@material-ui/icons/Info'
import styled from 'styled-components'
import {useApiGet} from '../utils/api'
import {makeStyles} from '@material-ui/core/styles'
import {DATETIME_FORMAT} from '../utils/date'
import {DateTime} from 'luxon'

const Spacing = styled.div`
  height: 20px;
`

interface Contact {
  id: any
  name: string
  account_number: string
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

interface Transfer {
  date_created: string
  id: any
  sender_user: User
  sender_account: Account
  recipient: Contact
  title: string
  amount: string
  pending: boolean
  frozen_account_number?: string
  date_confirmed?: string
  failed: boolean
}

const useStyles = makeStyles(theme => ({
  root: {
    width: '100%',
    maxWidth: '36ch',
    backgroundColor: theme.palette.background.paper,
  },
  title: {
    display: 'block',
  },
  inlineIncoming: {
    display: 'inline',
    color: 'rgb(54, 139, 54)',
  },
  inlineOutgoing: {
    display: 'inline',
    color: 'rgb(164, 69, 69)',
  },
}))

interface TransferProps {
  transfer: Transfer
  me: User
}

interface TransferWrapperProps {
  failed: boolean
}

const TransferWrapper = styled.div<TransferWrapperProps>`
  ${props =>
    props.failed &&
    `
    > * {
        text-decoration: line-through;
      color: grey !important;
    }
  `}
`

function Transfer({transfer, me}: TransferProps) {
  const classes = useStyles()

  const outgoing = me.id === transfer.sender_user.id

  return (
    <Fragment>
      <ListItemAvatar>
        <Avatar>
          {outgoing ? <ArrowForwardIcon /> : <ArrowDownwardIcon />}
        </Avatar>
      </ListItemAvatar>
      <TransferWrapper failed={transfer.failed}>
        <ListItemText
          primary={`Przelew ${outgoing ? 'wychodzący:' : 'przychodzący'} ${
            outgoing ? transfer.recipient.name : ''
          }`}
          secondary={
            <React.Fragment>
              <Typography
                component="span"
                variant="body2"
                className={classes.title}
                color="textPrimary"
              >
                {transfer.title}
              </Typography>
              <Typography
                component="span"
                variant="body2"
                className={
                  outgoing ? classes.inlineOutgoing : classes.inlineIncoming
                }
                color="textPrimary"
              >
                {`${outgoing ? '-' : '+'}${transfer.amount}`}
              </Typography>
              {transfer.date_confirmed &&
                !transfer.failed &&
                ` — Zrealizowany ${DateTime.fromISO(
                  transfer.date_confirmed,
                ).toFormat(DATETIME_FORMAT)}`}
            </React.Fragment>
          }
        />
      </TransferWrapper>
      {transfer.date_confirmed && (
        <ListItemSecondaryAction>
          <Link to={`/transfers/${transfer.id}`}>
            <IconButton edge="end">
              <InfoIcon />
            </IconButton>
          </Link>
        </ListItemSecondaryAction>
      )}
    </Fragment>
  )
}

const ListWrapper = styled.div`
  width: 100%;
  max-width: 600px;
`

export default function AllTransfersPage() {
  const {data: data, isPending} = useApiGet(
    `${process.env.REACT_APP_API_URL}/transfers/?full_serializer=true`,
  )
  const {data: me, isPending: isMePending} = useApiGet<User>(
    `${process.env.REACT_APP_API_URL}/users/me/`,
  )

  let pendingTransfers = null
  let finishedTransfers = null

  if (isPending || isMePending || !me) {
    return <CircularProgress />
  }

  if (data) {
    pendingTransfers = data.filter((transfer: Transfer) => transfer.pending)
    finishedTransfers = data.filter((transfer: Transfer) => !transfer.pending)
  }

  return (
    <Fragment>
      <Grid container alignItems="center" spacing={5}>
        <Grid item>
          <Link to="/transfers/new">
            <Button
              variant="contained"
              color="primary"
              size="large"
              startIcon={<PersonAddIcon />}
            >
              Nowy przelew
            </Button>
          </Link>
        </Grid>
      </Grid>
      {pendingTransfers && pendingTransfers.length > 0 && (
        <Fragment>
          <Spacing />
          <Typography variant="h5">Oczekujące przelewy</Typography>
          <ListWrapper>
            <List>
              {pendingTransfers &&
                pendingTransfers.length > 0 &&
                pendingTransfers.map((transfer: Transfer) => (
                  <ListItem key={transfer.id}>
                    <Transfer transfer={transfer} me={me} />
                  </ListItem>
                ))}
            </List>
          </ListWrapper>
        </Fragment>
      )}
      <Spacing />
      <Typography variant="h5">Zrealizowane przelewy</Typography>
      <ListWrapper>
        <List>
          {finishedTransfers && finishedTransfers.length === 0 && (
            <div>Brak przelewów.</div>
          )}
          {finishedTransfers &&
            finishedTransfers.length > 0 &&
            finishedTransfers.map((transfer: Transfer) => (
              <ListItem key={transfer.id}>
                <Transfer transfer={transfer} me={me} />
              </ListItem>
            ))}
        </List>
      </ListWrapper>
    </Fragment>
  )
}
