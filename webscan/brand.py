"""Shared WS-R version and HTTP identity."""
NAME = 'The World Is Yours'
VERSION = '5.0.0'
USER_AGENT = 'TWIY/' + VERSION

# Original ASCII globe/pedestal and Miami palms, inspired by the film's visual
# motif. Keep it text-only, markup-free and usable without Rich or ANSI support.
SCARFACE_ART = r'''
       \  |  /              .-========-.              \  |  /
     ---\ | /---          .'  .--..--.  '.          ---\ | /---
         \|/            /   /    ||    \   \            \|/
          |            |---|-----++-----|---|            |
          |            |   |     ||     |   |            |
         /|\            \   \    ||    /   /            /|\
        / | \            '.  '--''--'  .'            / | \
                           '-.____.-'
                            /  /\  \
                           /__/  \__\
                          /___/\___\
                         |          |
                      ___|__________|___
                     /__________________\
       ___________________________________________________
                   S C A R F A C E   E D I T I O N
'''.strip('\n')

COMPACT_ART = r'''
             .-=======-.
            /  .--+--.  \
           |---|--+--|---|
            \  '--+--'  /
             '-._____.-'
                /|\
             __/_|_\__
            |_________|
         S C A R F A C E
'''.strip('\n')
