rule Regra_exemplo : tag
{
	meta:
		author: Lucas T. A. Gouvêa [lucas.fim@gmail.com]
		description: Regra que marca arquivos por tamanho ou por casamento de string
		date: 2016

	strings:
		$string_hex = { E2 34  A1 C8 23 FB }

	condition:
		(filesize < 2MB) or $string_hex
}