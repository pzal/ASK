import React, {Fragment} from 'react'
import {Link} from 'react-router-dom'
import List from '@material-ui/core/List'
import ListItem from '@material-ui/core/ListItem'
import ListItemAvatar from '@material-ui/core/ListItemAvatar'
import Button from '@material-ui/core/Button'
import Grid from '@material-ui/core/Grid'
import ListItemText from '@material-ui/core/ListItemText'
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction'
import Avatar from '@material-ui/core/Avatar'
import PersonIcon from '@material-ui/icons/Person'
import EditIcon from '@material-ui/icons/Edit'
import PersonAddIcon from '@material-ui/icons/PersonAdd'
import IconButton from '@material-ui/core/IconButton'
import styled from 'styled-components'
import {useApiGet} from '../utils/api'

const ListWrapper = styled.div`
  width: 100%;
  max-width: 600px;
`

export default function ContactsPage() {
  const {data: response} = useApiGet(
    `${process.env.REACT_APP_API_URL}/users/contacts/`,
  )

  return (
    <Fragment>
      <Grid container alignItems="center" spacing={5}>
        {/* <Grid item>
          <Typography variant="h5">Lista kontaktów</Typography>
        </Grid> */}
        <Grid item>
          <Link to="/contacts/new">
            <Button
              variant="contained"
              color="primary"
              size="large"
              startIcon={<PersonAddIcon />}
            >
              Nowy kontakt
            </Button>
          </Link>
        </Grid>
      </Grid>
      <ListWrapper>
        <List>
          {response?.map(
            (contact: {name: string; id: string; account_number: string}) => (
              <ListItem key={contact.id}>
                <ListItemAvatar>
                  <Avatar>
                    <PersonIcon />
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary={contact.name}
                  secondary={contact.account_number}
                />
                <ListItemSecondaryAction>
                  <Link to={`/contacts/${contact.id}`}>
                    <IconButton edge="end" aria-label="delete">
                      <EditIcon />
                    </IconButton>
                  </Link>
                </ListItemSecondaryAction>
              </ListItem>
            ),
          )}
        </List>
      </ListWrapper>
    </Fragment>
  )
}
