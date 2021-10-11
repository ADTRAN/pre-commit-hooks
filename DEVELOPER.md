# Developing

## Installing

You will need to install `tox` like this:

```
python3 -m pip install --user tox
```

## Testing

```
tox -e pre-commit
tox -e py36
tox -e py37
tox -e py38
```

## Update requirements in setup.cfg

```
tox -e py36-update-requirements
```
