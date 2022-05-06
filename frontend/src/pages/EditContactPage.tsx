import React, {Fragment} from 'react'
import Button from '@material-ui/core/Button'
import Grid from '@material-ui/core/Grid'
import TextField from '@material-ui/core/TextField'
import SaveIcon from '@material-ui/icons/Save'
import Alert from '@material-ui/lab/Alert'
import IconButton from '@material-ui/core/IconButton'
import Collapse from '@material-ui/core/Collapse'
import CloseIcon from '@material-ui/icons/Close'
import DeleteIcon from '@material-ui/icons/Delete'
import Dialog from '@material-ui/core/Dialog'
import DialogActions from '@material-ui/core/DialogActions'
import DialogTitle from '@material-ui/core/DialogTitle'
import styled from 'styled-components'
import {apiPatch, apiDelete, useApiGet} from '../utils/api'
import {useParams, useHistory, Redirect} from 'react-router-dom'
import CircularProgress from '@material-ui/core/CircularProgress'

const ContentWrapper = styled.div`
  max-width: 700px;
`

interface Params {
  contactId: string
}

export default function EditContactPage() {
  const {contactId} = useParams<Params>()
  const history = useHistory()
  const {data: response, isPending, isRejected} = useApiGet(
    `${process.env.REACT_APP_API_URL}/users/contacts/${contactId}/`,
  )
  const [successToShow, setSuccessToShow] = React.useState<string | null>(null)
  const [failureToShow, setFailureToShow] = React.useState<string | null>(null)
  const [openDeleteDialog, setOpenDeleteDialog] = React.useState(false)
  const [name, setName] = React.useState<string | null>(null)
  const [accountNumber, setAccountNumber] = React.useState<string | null>(null)

  const onSave = () => {
    setSuccessToShow(null)
    setFailureToShow(null)

    const data = {} as any
    if (name !== null) {
      data['name'] = name
    }
    if (accountNumber !== null) {
      data['account_number'] = accountNumber
    }

    apiPatch(
      `${process.env.REACT_APP_API_URL}/users/contacts/${contactId}/`,
      data,
    )
      .then(res => {
        console.log('res', res)
        setSuccessToShow('Zmiany zapisane.')
      })
      .catch(err => {
        console.log('err', err)
        setFailureToShow('Nie udało się zapisać zmian.')
      })
  }

  const onDelete = () => {
    setSuccessToShow(null)
    setFailureToShow(null)

    apiDelete(`${process.env.REACT_APP_API_URL}/users/contacts/${contactId}/`)
      .then(res => {
        console.log('res', res)
        setSuccessToShow('Kontakt usunięty.')
        setTimeout(() => {
          history.replace('/contacts/all')
        }, 1000)
        setOpenDeleteDialog(false)
      })
      .catch(err => {
        console.log('err', err)
        setFailureToShow('Nie udało się usunąć kontaktu.')
        setOpenDeleteDialog(false)
      })
  }

  if (isPending) {
    return <CircularProgress />
  }

  if (isRejected) {
    return <Redirect to="/contacts/all" />
  }

  return (
    <Fragment>
      <ContentWrapper>
        <Grid container direction="column" spacing={2}>
          <Grid item>
            <TextField
              id="filled-helperText"
              label="Nazwa"
              value={(name === null ? response?.name : name) || ''}
              onChange={e => setName(e.target.value)}
              fullWidth
              variant="filled"
            />
          </Grid>
          <Grid item>
            <TextField
              id="filled-helperText"
              label="Numer konta"
              value={
                (accountNumber === null
                  ? response?.account_number
                  : accountNumber) || ''
              }
              onChange={e => setAccountNumber(e.target.value)}
              fullWidth
              variant="filled"
            />
          </Grid>
          <Grid item>
            <Button
              onClick={onSave}
              variant="contained"
              color="primary"
              size="large"
              startIcon={<SaveIcon />}
            >
              Zapisz
            </Button>
          </Grid>
          <Grid item>
            <Button
              onClick={() => setOpenDeleteDialog(true)}
              variant="contained"
              size="large"
              startIcon={<DeleteIcon />}
            >
              Usuń kontakt
            </Button>
          </Grid>
          <Grid item>
            <Collapse in={Boolean(successToShow)}>
              <Alert
                severity="success"
                action={
                  <IconButton
                    aria-label="close"
                    color="inherit"
                    size="small"
                    onClick={() => {
                      setSuccessToShow(null)
                    }}
                  >
                    <CloseIcon fontSize="inherit" />
                  </IconButton>
                }
              >
                {successToShow}
              </Alert>
            </Collapse>
            <Collapse in={Boolean(failureToShow)}>
              <Alert
                severity="error"
                action={
                  <IconButton
                    aria-label="close"
                    color="inherit"
                    size="small"
                    onClick={() => {
                      setFailureToShow(null)
                    }}
                  >
                    <CloseIcon fontSize="inherit" />
                  </IconButton>
                }
              >
                {failureToShow}
              </Alert>
            </Collapse>
            <Dialog
              open={openDeleteDialog}
              onClose={() => setOpenDeleteDialog(false)}
            >
              <DialogTitle>Na pewno chcesz usunąć kontakt?</DialogTitle>
              <DialogActions>
                <Button onClick={onDelete} color="secondary">
                  Usuń
                </Button>
                <Button
                  onClick={() => setOpenDeleteDialog(false)}
                  color="primary"
                  autoFocus
                >
                  Anuluj
                </Button>
              </DialogActions>
            </Dialog>
          </Grid>
        </Grid>
      </ContentWrapper>
    </Fragment>
  )
}
