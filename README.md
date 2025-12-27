# PassBasedAuthAnzalyzer

## GROUND_SEED
Used python in order to calculate GROUP_SEED, the way we did it is listed below
```python
a = 323079129
b = 212071120
result = a ^ b
print(result)
```
output is:
`534919433`

## Password selection

### Weak
source is from here: https://en.wikipedia.org/wiki/List_of_the_most_common_passwords

We chose by these requirements:
- very common passwords

### Medium
reference from here: https://en.wikipedia.org/wiki/Password_policy

requirements: 
- At least 8 characters
- At least 1 uppercase, 1 lowercase and 1 digit

### Strong
requirements: 
- At least 12 characters
- At least 1 uppercase, 1 lowercase, 1 digit and 1 symbol
- Strings in order are not allowed, such as 123, or abc
