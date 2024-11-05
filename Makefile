NAME		=	ft_nmap

CC			=	gcc

##
##		FILE DESCRIPTOR
##

INCLUDE = includes lib_arg_parsing/includes

SRC_PATH = srcs

SRCS =	globals.c			\
		main.c				\
		parsing.c			\
		pcap_parsing.c		\
		packet_parsing.c	\
		verbose.c			\
		lookup.c			\
		sending.c	


##
##		SETTING VPATH
##

vpath %.c $(foreach dir, $(SRC_PATH), $(dir):)


##
##		DEPENDENCE DESCRIPTOR
##

IDEP = includes/ft_nmap.h lib_arg_parsing/includes/lib_arg_parsing.h lib_arg_parsing/includes/lib_arg_parsing_structs.h

OBJ_PATH = objs

OBJS = $(addprefix $(OBJ_PATH)/, $(SRCS:.c=.o))

##
##		LIB DESCRIPTOR
##

LIBAGP_PATH	=	lib_arg_parsing
LIBNAME		=	_arg_parsing
LIBPATH		=	$(LIBAGP_PATH)
LIBHEAD		=	$(LIBAGP_PATH)/includes/lib_arg_parsing.h

##
##		FLAGS CONSTRUCTION
##

CFLAGS = -Wall -Wextra -Werror #-fsanitize=address -g3
LFLAGS = -lpcap

IFLAGS = 	$(foreach dir, $(INCLUDE), -I$(dir) ) \

LFLAGS +=	$(foreach path, $(LIBPATH), -L$(path) ) \
			$(foreach lib, $(LIBNAME), -l$(lib) ) \

$(OBJ_PATH)/%.o:	%.c $(IDEP)
	$(CC) -c $< -o $@ $(CFLAGS) $(IFLAGS) $(LFLAGS)


all:		$(NAME)

$(NAME):	$(OBJ_PATH) $(OBJS)
	cd $(LIBPATH) && $(MAKE)
	$(CC) -o $(NAME) $(OBJS) $(CFLAGS) $(LFLAGS) $(IFLAGS)

clean:
	make clean -C $(LIBAGP_PATH)
	rm -rf $(OBJ_PATH)

fclean: clean
	make fclean -C $(LIBAGP_PATH)
	rm -rf $(NAME)

$(OBJ_PATH):
	mkdir $(OBJ_PATH)

re:			fclean all

.SILENT:	all $(NAME) fclean clean re 
.PHONY:		clean fclean re