SQLite format 3   @                                                                     .WJ� 
: j��3�
:d                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                �'33�utablepublication_authorspublication_authorsCREATE TABLE publication_authors (
	user_id INTEGER NOT NULL, 
	publication_id INTEGER NOT NULL, 
	PRIMARY KEY (user_id, publication_id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	FOREIGN KEY(publication_id) REFERENCES publications (id)
)EY3 indexsqlite_autoindex_publication_authors_1publication_authors�%%�MtablepublicationspublicationsCREATE TABLE publications (
	id INTEGER NOT NULL, 
	intituler VARCHAR(256), 
	description VARCHAR(900), 
	image VARCHAR(900), 
	is_validate BOOLEAN, 
	status VARCHAR(256), 
	created_date DATETIME, 
	owner_id INTEGER, 
	user_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(owner_id) REFERENCES signales (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
)��tablenotesnotesCREATE TABLE notes (
	id INTEGER NOT NULL, 
	commentaire VARCHAR(900), 
	etoile INTEGER, 
	created_date DATETIME, 
	PRIMARY KEY (id)
)��{tablesignalessignalesCREATE TABLE signales (
	id INTEGER NOT NULL, 
	commentaire VARCHAR(900), 
	created_date DATETIME, 
	PRIMARY KEY (id)
)�`�tableusersusersCREATE TABLE users (
	id INTEGER NOT NULL, 
	firs_name VARCHAR(256), 
	last_name VARCHAR(256), 
	phone_nomber VARCHAR(256), 
	email VARCHAR, 
	type VARCHAR(256), 
	description VARCHAR(800), 
	profile VARCHAR(900), 
	hashed_password VARCHAR(256), 
	disabled BOOLEAN, 
	created_date DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (email)
))= indexsqlite_autoindex_users_1users          � {�                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                }    /  �Astiving@gmail.comemployeur$2b$12$DcMLTQUFAW.FWlE8htKWBuGBWHB6DT5NDRYIBaAPtLFz0LadR/QDa2022-08-31 12:48:43.183836�    9  �Astivingtatga@gmail.comquandidat$2b$12$/vXhv.9hHul.WFrU83Y3Eewox6YBdr4hbvT49SIbDkSyvwcaUO3822022-08-31 12:25:02.898598
   � ��                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    /stiving@gmail.com9	stivingtatga@gmail.com                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            � � �Z�                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ?
 - 	A FooA very nice Itemactiver2022-08-31 13:32:48.055913A
 - 	!A 	FooA very nice Itemdesactiver2022-08-30 17:31:23.471775D
 1 	A videurbesoin d'un videuractiver2022-08-31 12:57:09.787773d
 m 	A 	vaissellebesoin dune personne serieuse pour une vaisselleactiver2022-08-31 12:46:27.540923   @- 	A 	FooA very nice Itemactiver2022-08-30 17:31:23.471775                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              