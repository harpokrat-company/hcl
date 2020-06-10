//
// Created by antoine on 10/06/2020.
//

#ifndef HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_TESTNICO_H_
#define HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_TESTNICO_H_

#include "../AutoRegisterer.h"
#include "APrimeGenerator.h"

namespace HCL::Crypto {

	class TestNico : public AutoRegisterer<APrimeGenerator, TestNico> {
	public:
		TestNico();

		// Ajouter les méthodes de gestion des dépendances (dans ce cas, PrimeVerifier ? (algo de vérification de primalité))
		// BLABLA

		// Penser au Nom + Type + id / ! \ !
		const std::string &GetElementName() const override { return GetName(); };
		const std::string &GetElementTypeName() const override { return GetTypeName(); };
		static const uint16_t id = 1;

	private:
		//Dépendance algo vérif primalité
	};
}

#endif //HCL_SRC_SERVICES_CRYPTO_PRIMEGENERATORS_TESTNICO_H_
