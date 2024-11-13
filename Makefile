NAME		=	ft_nmap

CC			=	gcc

##
##		FILE DESCRIPTOR
##

INCLUDE = includes

SRC_PATH = srcs

SRCS =	globals.c			\
		main.c				\
		parsing.c			\
		pcap_parsing.c		\
		packet_parsing.c	\
		verbose.c			\
		lookup.c			\
		sending.c			\
		thread_queue.c		\
		results.c			\
		answer_logic.c


##
##		SETTING VPATH
##

vpath %.c $(foreach dir, $(SRC_PATH), $(dir):)


##
##		DEPENDENCE DESCRIPTOR
##

IDEP = includes/ft_nmap.h 

OBJ_PATH = objs

OBJS = $(addprefix $(OBJ_PATH)/, $(SRCS:.c=.o))

##
##		FLAGS CONSTRUCTION
##

CFLAGS = -Wall -Wextra -Werror -fsanitize=address -g3
LFLAGS = -lpcap

IFLAGS = 	$(foreach dir, $(INCLUDE), -I$(dir) ) \

$(OBJ_PATH)/%.o:	%.c $(IDEP)
	$(CC) -c $< -o $@ $(CFLAGS) $(IFLAGS) $(LFLAGS)


all:		$(NAME)

$(NAME):	$(OBJ_PATH) $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(CFLAGS) $(LFLAGS) $(IFLAGS)

clean:
	rm -rf $(OBJ_PATH)

fclean: clean
	rm -rf $(NAME)

$(OBJ_PATH):
	mkdir $(OBJ_PATH)

re:			fclean all

.SILENT:	all $(NAME) fclean clean re 
.PHONY:		clean fclean re