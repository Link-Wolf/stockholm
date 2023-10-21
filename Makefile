# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: xxxxxxx <xxxxxxx@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2023/09/14 13:51:42 by xxxxxxx           #+#    #+#              #
#    Updated: 2023/09/14 13:51:43 by xxxxxxx          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME		=	stockholm

SRCS_FILE	=	stockholm		\
				Stockholm.class
SRCS_FOLD	= 	srcs/
SRCS		=	$(addsuffix .cpp, $(addprefix $(SRCS_FOLD), $(SRCS_FILE)))

INCS_FILE	=	stockholm		\
				constants		\
				Stockholm.class
INCS_FOLD	=	incs/
INCS		=	$(addsuffix .hpp, $(addprefix $(INCS_FOLD), $(INCS_FILE)))

OBJS		=	$(SRCS:.cpp=.o)

CC			=	c++
CFLAGS		=	-Wall -Wextra -Werror
RM			=	rm -f

all:			$(NAME)

$(NAME):		$(OBJS) $(CLASS_OBJS) $(INCS)
				$(CC) $(CFLAGS) $(OBJS) -o $(NAME)

.cpp.o:
				$(CC) $(CFLAGS) -c $< -o $@

clean:
				$(RM) $(OBJS)

fclean:			clean
				$(RM) $(NAME)

re:				fclean all

test:
				@rm -rf ~/infection/*
				@rm -rf ~/dossier_a_ne_pas_toucher

				@mkdir -p ~/infection/mon_sous_dossier

				@echo "Je suis un fichier txt" > ~/infection/texte.txt

				@echo "je suis classe, bg n'est il pas" > ~/infection/ma_classe.class

				@echo "camion ? pouet poueeeeeeet" > ~/infection/archive.zip
				@chmod 000 ~/infection/archive.zip

				@mkdir -p ~/dossier_a_ne_pas_toucher
				@echo "ohlala je ne devrai pas etre touché" > ~/dossier_a_ne_pas_toucher/je_suis_un_fichier.txt
				@ln -s ~/dossier_a_ne_pas_toucher/je_suis_un_fichier.txt ~/infection/lien_symbolique.cpp 

				@mkdir -p ~/infection/lien_symbolique_dossier
				@ln -s ~/dossier_a_ne_pas_toucher/ ~/infection/lien_symbolique_dossier

				@cp -r $(addsuffix .cpp, $(addprefix $(SRCS_FOLD), $(SRCS_FILE))) ~/infection/mon_sous_dossier

				@printf "Fichiers tests créés dans ~/infection"

.PHONY:			all clean fclean re .cpp.o test